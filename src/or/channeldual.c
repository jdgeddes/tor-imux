/* * Copyright (c) 2012-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file channeldual.c
 * \brief channel_t concrete subclass using or_connection_t
 **/

/*
 * Define this so channel.h gives us things only channel_t subclasses
 * should touch.
 */

#define TOR_CHANNEL_INTERNAL_

#include "or.h"
#include "channel.h"
#include "channeltls.h"
#include "channeldual.h"
#include "circuitmux.h"
#include "circuitmux_ewma.h"
#include "config.h"
#include "connection.h"
#include "connection_or.h"
#include "control.h"
#include "relay.h"
#include "router.h"
#include "routerlist.h"

#define NUMCONNECTIONS 2

typedef struct channel_dual_cell_t {
    cell_t cell;
    int minheap_idx;
} channel_dual_cell_t;

typedef enum channel_circuit_status_t {
    CIRC_LIGHT, CIRC_HEAVY, CIRC_INACTIVE,
} channel_circuit_status_t;

typedef struct channel_dual_circuit_t {
    circuit_t *circ;
    circid_t circ_id;
    channel_circuit_status_t status;
    int next_sequence;
    smartlist_t *cell_queue;

    or_connection_t *readconn;
    or_connection_t *writeconn;

    /* variables for EWMA calculations */
    int cell_count;
    unsigned int start_tick;
    unsigned int last_tick_update;
    double last_ewma;
    double ewma;
} channel_dual_circuit_t;

/**************************************
 * Hash table for connection entries
 **************************************/

typedef struct channel_dual_conn_entry_t {
    HT_ENTRY(channel_dual_conn_entry_t) node;
    tor_addr_t addr;
    channel_t *chan;
} channel_dual_conn_entry_t;

/** Map from channel to IP address */
static HT_HEAD(channel_map, channel_dual_conn_entry_t) channel_by_addr =
     HT_INITIALIZER();

/** Hashtable helper: compute a hash of a clientmap_entry_t. */
static INLINE unsigned
channel_map_entry_hash(const channel_dual_conn_entry_t *a)
{
  return ht_improve_hash(tor_addr_hash(&a->addr));
}
/** Hashtable helper: compare two channel_map_entry_t values for equality. */
static INLINE int
channel_map_entry_eq(const channel_dual_conn_entry_t *a, const channel_dual_conn_entry_t *b)
{
  return !tor_addr_compare(&a->addr, &b->addr, CMP_EXACT);
}

HT_PROTOTYPE(channel_map, channel_dual_conn_entry_t, node, channel_map_entry_hash,
             channel_map_entry_eq);
HT_GENERATE(channel_map, channel_dual_conn_entry_t, node, channel_map_entry_hash,
            channel_map_entry_eq, 0.6, malloc, realloc, free);


/* Utility function declarations */
static void channel_dual_common_init(channel_dual_t *dualchan);

/**
 * Do parts of channel_dual_t initialization common to channel_dual_connect()
 * and channel_dual_handle_incoming().
 */

static void
channel_dual_common_init(channel_dual_t *dualchan)
{
  channel_t *chan;

  tor_assert(dualchan);

  chan = &(dualchan->base_);
  channel_init(chan);
  chan->magic = DUAL_CHAN_MAGIC;
  chan->type = CHANNEL_TYPE_DUAL;
  chan->state = CHANNEL_STATE_OPENING;
  chan->close = channel_dual_close_method;
  chan->describe_transport = channel_dual_describe_transport_method;
  chan->get_remote_addr = channel_dual_get_remote_addr_method;
  chan->get_transport_name = channel_dual_get_transport_name_method;
  chan->get_remote_descr = channel_dual_get_remote_descr_method;
  chan->has_queued_writes = channel_dual_has_queued_writes_method;
  chan->is_canonical = channel_dual_is_canonical_method;
  chan->free = channel_dual_free_method;
  chan->matches_extend_info = channel_dual_matches_extend_info_method;
  chan->matches_target = channel_dual_matches_target_method;
  chan->write_cell = channel_dual_write_cell_method;
  chan->write_packed_cell = channel_dual_write_packed_cell_method;
  chan->write_var_cell = channel_dual_write_var_cell_method;

  chan->cmux = circuitmux_alloc();
  if (cell_ewma_enabled()) {
    circuitmux_set_policy(chan->cmux, &ewma_policy);
  }
}

/**
 * Start a new DUAL channel
 *
 * Launch a new OR connection to <b>addr</b>:<b>port</b> and expect to
 * handshake with an OR with identity digest <b>id_digest</b>, and wrap
 * it in a channel_dual_t.
 */

channel_t *
channel_dual_connect(const tor_addr_t *addr, uint16_t port,
                    const char *id_digest)
{
  channel_dual_t *dualchan = tor_malloc_zero(sizeof(*dualchan));
  channel_t *chan = &(dualchan->base_);
  int i;

  channel_dual_common_init(dualchan);

  log_debug(LD_CHANNEL,
            "In channel_dual_connect() for channel %p "
            "(global id " U64_FORMAT ")",
            dualchan,
            U64_PRINTF_ARG(chan->global_identifier));

  if (is_local_addr(addr)) channel_mark_local(chan);
  channel_mark_outgoing(chan);

  tor_addr_copy(&(dualchan->addr), addr);
  dualchan->port = port;
  memcpy(dualchan->id_digest, id_digest, DIGEST_LEN);
  dualchan->circuits = smartlist_new();
  dualchan->connections = smartlist_new();

  for(i = 0; i < NUMCONNECTIONS; i++) {
    or_connection_t *conn;

    log_info(LD_CHANNEL, "creating connection %d for dual chan", i + 1);

    dualchan->newconn = &(conn);
    conn = connection_or_connect(addr, port, id_digest, chan);

    if (!conn) {
      log_warn(LD_CHANNEL, "Error creating connection %d, move to CHANNEL_STATE_ERROR", i + 1);
      chan->reason_for_closing = CHANNEL_CLOSE_FOR_ERROR;
      channel_change_state(chan, CHANNEL_STATE_ERROR);
      goto err;
    }

    smartlist_add(dualchan->connections, conn);

    log_info(LD_CHANNEL, "created connection %d on channel id " U64_FORMAT ".",
        i + 1, U64_PRINTF_ARG(chan->global_identifier));
  }

  goto done;

 err:
  circuitmux_free(chan->cmux);
  tor_free(dualchan);
  chan = NULL;

 done:
  /* If we got one, we should register it */
  if (chan) {
      channel_register(chan);
      chan->type = CHANNEL_TYPE_DUAL;
  }

  return chan;
}

/**
 * Create a new channel around an incoming or_connection_t
 */

channel_t *
channel_dual_create_incoming(tor_addr_t addr)
{
  channel_dual_t *dualchan = tor_malloc_zero(sizeof(*dualchan));
  channel_t *chan = &(dualchan->base_);
  chan->type = CHANNEL_TYPE_DUAL;

  channel_dual_common_init(dualchan);

  tor_addr_copy(&(dualchan->addr), &addr);
  dualchan->circuits = smartlist_new();
  dualchan->connections = smartlist_new();

  log_info(LD_CHANNEL, "creating incoming dual channel connection %p on address %s", dualchan, fmt_addr(&(dualchan->addr)));


  if (is_local_addr(&addr)) channel_mark_local(chan);
  channel_mark_incoming(chan);

  /* If we got one, we should register it */
  if (chan) {
      channel_register(chan);
      chan->type = CHANNEL_TYPE_DUAL;
  }

  return chan;
}

channel_t *
channel_dual_handle_incoming(or_connection_t *orconn)
{
  tor_assert(orconn);
  tor_assert(!(orconn->chan));

  tor_addr_t addr = TO_CONN(orconn)->addr;

  channel_dual_conn_entry_t lookup, *ent;

  tor_addr_copy(&lookup.addr, &(addr));
  ent = HT_FIND(channel_map, &channel_by_addr, &lookup);

  if(!ent) {
      ent = tor_malloc_zero(sizeof(*ent));
      tor_addr_copy(&(ent->addr), &(addr));
      ent->chan = channel_dual_create_incoming(addr);
      HT_INSERT(channel_map, &channel_by_addr, ent);
  }

  channel_t *chan = ent->chan;
  channel_dual_t *dualchan = BASE_CHAN_TO_DUAL(chan);
  smartlist_add(dualchan->connections, orconn);

  orconn->chan = chan;

  return chan;
}

void
channel_dual_free_method(channel_t *chan)
{
  tor_assert(chan);

  channel_dual_t *dualchan = BASE_CHAN_TO_DUAL(chan);

  channel_dual_conn_entry_t lookup, *ent;
  log_warn(LD_CHANNEL, "freeing dualchan %p at address %s", dualchan, fmt_addr(&(dualchan->addr)));

  tor_addr_copy(&lookup.addr, &(dualchan->addr));
  ent = HT_FIND(channel_map, &channel_by_addr, &lookup);

  if(ent) {
      HT_REMOVE(channel_map, &channel_by_addr, ent);
      tor_free(ent);
  } else {
    log_warn(LD_CHANNEL, "could not find channel for %s to close (%p)", fmt_addr(&(dualchan->addr)), dualchan);
  }
}

/*********
 * Casts *
 ********/

/**
 * Cast a channel_dual_t to a channel_t.
 */

channel_t *
channel_dual_to_base(channel_dual_t *dualchan)
{
  if (!dualchan) return NULL;

  return &(dualchan->base_);
}

/**
 * Cast a channel_t to a channel_dual_t, with appropriate type-checking
 * asserts.
 */

channel_dual_t *
channel_dual_from_base(channel_t *chan)
{
  if (!chan) return NULL;

  tor_assert(chan->magic == DUAL_CHAN_MAGIC);

  return (channel_dual_t *)(chan);
}

/********************************************
 * Method implementations for channel_dual_t *
 *******************************************/

/**
 * Close a channel_dual_t
 *
 * This implements the close method for channel_dual_t
 */

void
channel_dual_close_method(channel_t *chan)
{
  channel_dual_t *dualchan = BASE_CHAN_TO_DUAL(chan);

  tor_assert(dualchan);


  if(dualchan->lightconn) connection_or_close_normally(dualchan->lightconn, 1);
  if(dualchan->heavyconn) connection_or_close_normally(dualchan->heavyconn, 1);

  channel_dual_conn_entry_t lookup, *ent;

  tor_addr_copy(&lookup.addr, &(dualchan->addr));
  ent = HT_FIND(channel_map, &channel_by_addr, &lookup);

  if(ent) {
      HT_REMOVE(channel_map, &channel_by_addr, ent);
      tor_free(ent);
  } else {
    log_warn(LD_CHANNEL, "could not find channel for %s to close", fmt_addr(&(dualchan->addr)));
  }

  //if(!dualchan->lightconn && !dualchan->heavyconn) {
  //  /* Weird - we'll have to change the state ourselves, I guess */
  //  log_info(LD_CHANNEL,
  //           "Tried to close channel_dual_t %p with NULL conn",
  //           dualchan);
  //  channel_change_state(chan, CHANNEL_STATE_ERROR);
  //}
}

/**
 * Describe the transport for a channel_dual_t
 *
 * This returns the string "DUAL channel on connection <id>" to the upper
 * layer.
 */

const char *
channel_dual_describe_transport_method(channel_t *chan)
{
  char *buf = NULL;
  uint64_t id;
  channel_dual_t *dualchan;
  const char *rv = NULL;

  tor_assert(chan);

  dualchan = BASE_CHAN_TO_DUAL(chan);

  if (dualchan->lightconn) {
    id = TO_CONN(dualchan->lightconn)->global_identifier;

    if (buf) tor_free(buf);
    tor_asprintf(&buf,
                 "DUAL channel (connection " U64_FORMAT ")",
                 U64_PRINTF_ARG(id));

    rv = buf;
  } else {
    rv = "DUAL channel (no connection)";
  }

  return rv;
}

/**
 * Get the remote address of a channel_dual_t
 *
 * This implements the get_remote_addr method for channel_dual_t; copy the
 * remote endpoint of the channel to addr_out and return 1 (always
 * succeeds for this transport).
 */

int
channel_dual_get_remote_addr_method(channel_t *chan, tor_addr_t *addr_out)
{
  channel_dual_t *dualchan = BASE_CHAN_TO_DUAL(chan);

  tor_assert(dualchan);
  tor_assert(addr_out);

  tor_addr_copy(addr_out, &dualchan->addr);

  return 1;
}

/**
 * Get the name of the pluggable transport used by a channel_dual_t.
 *
 * This implements the get_transport_name for channel_dual_t. If the
 * channel uses a pluggable transport, copy its name to
 * <b>transport_out</b> and return 0. If the channel did not use a
 * pluggable transport, return -1. */

int
channel_dual_get_transport_name_method(channel_t *chan, char **transport_out)
{
  channel_dual_t *dualchan = BASE_CHAN_TO_DUAL(chan);

  tor_assert(dualchan);
  tor_assert(transport_out);
  tor_assert(smartlist_len(dualchan->connections));

  or_connection_t *conn = (or_connection_t *)smartlist_get(dualchan->connections, 0);

  if (!conn->ext_or_transport)
    return -1;

  *transport_out = tor_strdup(conn->ext_or_transport);
  return 0;
}

/**
 * Get endpoint description of a channel_dual_t
 *
 * This implements the get_remote_descr method for channel_dual_t; it returns
 * a text description of the remote endpoint of the channel suitable for use
 * in log messages.  The req parameter is 0 for the canonical address or 1 for
 * the actual address seen.
 */

const char *
channel_dual_get_remote_descr_method(channel_t *chan, int flags)
{
#define MAX_DESCR_LEN 32

  char buf[MAX_DESCR_LEN + 1];
  channel_dual_t *dualchan = BASE_CHAN_TO_DUAL(chan);
  connection_t *conn;
  const char *answer = NULL;
  char *addr_str;

  tor_assert(dualchan);
  tor_assert(smartlist_len(dualchan->connections));

  conn = TO_CONN((or_connection_t *)smartlist_get(dualchan->connections, 0));

  switch (flags) {
    case 0:
      /* Canonical address with port*/
      tor_snprintf(buf, MAX_DESCR_LEN + 1,
                   "%s:%u", conn->address, conn->port);
      answer = buf;
      break;
    case GRD_FLAG_ORIGINAL:
      /* Actual address with port */
      addr_str = tor_dup_addr(&(dualchan->addr));
      tor_snprintf(buf, MAX_DESCR_LEN + 1,
                   "%s:%u", addr_str, conn->port);
      tor_free(addr_str);
      answer = buf;
      break;
    case GRD_FLAG_ADDR_ONLY:
      /* Canonical address, no port */
      strlcpy(buf, conn->address, sizeof(buf));
      answer = buf;
      break;
    case GRD_FLAG_ORIGINAL|GRD_FLAG_ADDR_ONLY:
      /* Actual address, no port */
      addr_str = tor_dup_addr(&(dualchan->addr));
      strlcpy(buf, addr_str, sizeof(buf));
      tor_free(addr_str);
      answer = buf;
      break;

    default:
      /* Something's broken in channel.c */
      tor_assert(1);
  }

  return answer;
}

/**
 * Tell the upper layer if we have queued writes
 *
 * This implements the has_queued_writes method for channel_dual t_; it returns
 * 1 iff we have queued writes on the outbuf of the underlying or_connection_t.
 */

int
channel_dual_has_queued_writes_method(channel_t *chan)
{
  channel_dual_t *dualchan = BASE_CHAN_TO_DUAL(chan);

  tor_assert(dualchan);

  SMARTLIST_FOREACH_BEGIN(dualchan->connections, or_connection_t *, conn)
  {
      if(connection_get_outbuf_len(TO_CONN(conn)) > 0) {
          return 1;
      }
  }
  SMARTLIST_FOREACH_END(conn);

  return 0;
}

/**
 * Tell the upper layer if we're canonical
 *
 * This implements the is_canonical method for channel_dual_t; if req is zero,
 * it returns whether this is a canonical channel, and if it is one it returns
 * whether that can be relied upon.
 */

int
channel_dual_is_canonical_method(channel_t *chan, int req)
{
  int answer = 0;
  channel_dual_t *dualchan = BASE_CHAN_TO_DUAL(chan);

  tor_assert(dualchan);
  tor_assert(smartlist_len(dualchan->connections));

  or_connection_t *conn = smartlist_get(dualchan->connections, 0);

  switch (req) {
    case 0:
      answer = conn->is_canonical;
      break;
    case 1:
      /*
       * Is the is_canonical bit reliable?  In protocols version 2 and up
       * we get the canonical address from a NETINFO cell, but in older
       * versions it might be based on an obsolete descriptor.
       */
      answer = (conn->link_proto >= 2);
      break;
    default:
      /* This shouldn't happen; channel.c is broken if it does */
      tor_assert(1);
  }

  return answer;
}

/**
 * Check if we match an extend_info_t
 *
 * This implements the matches_extend_info method for channel_dual_t; the upper
 * layer wants to know if this channel matches an extend_info_t.
 */

int
channel_dual_matches_extend_info_method(channel_t *chan,
                                       extend_info_t *extend_info)
{
  channel_dual_t *dualchan = BASE_CHAN_TO_DUAL(chan);

  tor_assert(dualchan);
  tor_assert(extend_info);

  SMARTLIST_FOREACH_BEGIN(dualchan->connections, or_connection_t *, conn)
  {
      if(tor_addr_eq(&(extend_info->addr), &(TO_CONN(conn)->addr)) &&
        (extend_info->port == TO_CONN(conn)->port))
      {
          return 1;
      }
  }
  SMARTLIST_FOREACH_END(conn);


  return 0;
}

/**
 * Check if we match a target address; return true iff we do.
 *
 * This implements the matches_target method for channel_dual t_; the upper
 * layer wants to know if this channel matches a target address when extending
 * a circuit.
 */

int
channel_dual_matches_target_method(channel_t *chan,
                                  const tor_addr_t *target)
{
  channel_dual_t *dualchan = BASE_CHAN_TO_DUAL(chan);

  tor_assert(dualchan);
  tor_assert(target);

  return tor_addr_eq(&(dualchan->addr), target);
}

channel_dual_circuit_t *channel_dual_find_circuit(channel_dual_t *dualchan, circid_t circ_id)
{
    tor_assert(dualchan);

    SMARTLIST_FOREACH_BEGIN(dualchan->circuits, channel_dual_circuit_t *, c)
    {
        if(c->circ_id == circ_id)
            return c;
    }
    SMARTLIST_FOREACH_END(c);

    return NULL;
}

void
channel_dual_update_circuit_ewma(channel_dual_t *dualchan, circid_t circ_id)
{
    tor_assert(dualchan);

    channel_dual_circuit_t *dualcirc = channel_dual_find_circuit(dualchan, circ_id);
    if(!dualcirc) {
        log_warn(LD_CHANNEL, "could not find circuit %u", circ_id);
        return;
    }

    if(get_options()->DualUseTrafficTracker) {
      if(dualcirc->circ) {
        if(dualcirc->circ->traffic_type == TRAFFIC_TYPE_WEB) {
          dualcirc->writeconn = dualchan->lightconn;
        } else if(dualcirc->circ->traffic_type == TRAFFIC_TYPE_BULK) {
          dualcirc->writeconn = dualchan->heavyconn;
        }
      }

      return;
    }

    int switch_at_exit = get_options()->DualSwitchAtExit;
    double alpha = get_options()->DualEwmaAlpha;
    //double beta = get_options()->DualEwmaBeta;
    double threshold_light = get_options()->DualThresholdLight;
    double threshold_heavy = get_options()->DualThresholdHeavy;

    unsigned int now = approx_time();

    if(!dualcirc->start_tick) {
        /* EWMA varaibles */
        dualcirc->start_tick = now;
        dualcirc->last_tick_update = now;
    }

    int seconds_elapsed = now - dualcirc->last_tick_update;
    dualcirc->cell_count += 1;

    if(dualcirc->last_tick_update - dualcirc->start_tick < 10) {
        dualcirc->last_tick_update = now;
    } else if(seconds_elapsed >= 1) {
        double last_ewma = dualcirc->last_ewma;

        int i;
        for(i = 0; i < seconds_elapsed; i++) {
            dualcirc->ewma = (double)(1 - alpha) * dualcirc->last_ewma;
            dualcirc->last_ewma = dualcirc->ewma;
        }
        dualcirc->ewma += alpha * dualcirc->cell_count;

        log_info(LD_CHANNEL, "circuit %u went from EWMA %f to %f, cell count was %d and seconds elapsed %d  (n_chan=%p)",
                circ_id, last_ewma, dualcirc->ewma, dualcirc->cell_count, seconds_elapsed, dualcirc->circ->n_chan);

        dualcirc->cell_count = 0;
        dualcirc->last_tick_update = now;
        dualcirc->last_ewma = dualcirc->ewma;

        double ewma_diff = (dualcirc->ewma - last_ewma);

        if(dualcirc->status == CIRC_LIGHT) {
            dualchan->light_ewma_total += ewma_diff;

            double light_ewma_avg = (double)dualchan->light_ewma_total / (double)dualchan->light_circuit_count;
            if(dualcirc->ewma > light_ewma_avg * threshold_light) {
                dualcirc->status = CIRC_HEAVY; 
                if(!(dualcirc->circ->n_chan) || !switch_at_exit) {
                    dualcirc->writeconn = dualchan->heavyconn;
                    log_info(LD_CHANNEL, "EWMA switching over circuit %u to heavy connection", circ_id);
                }

                dualchan->light_ewma_total -= dualcirc->ewma;
                dualchan->light_circuit_count -= 1;

                dualchan->heavy_ewma_total += dualcirc->ewma;
                dualchan->heavy_circuit_count += 1;
            }
        } else if(dualcirc->status == CIRC_HEAVY) {
            dualchan->heavy_ewma_total += ewma_diff;

            double heavy_ewma_avg = (double)dualchan->heavy_ewma_total / (double)dualchan->heavy_circuit_count;
            if(dualcirc->ewma < heavy_ewma_avg * threshold_heavy) {
                dualcirc->status = CIRC_LIGHT;
                if(!(dualcirc->circ->n_chan) || !switch_at_exit) {
                    dualcirc->writeconn = dualchan->lightconn;
                    log_info(LD_CHANNEL, "EWMA switching over circuit %u to light connection", circ_id);
                }

                dualchan->heavy_ewma_total -= dualcirc->ewma;
                dualchan->heavy_circuit_count -= 1;

                dualchan->light_ewma_total += dualcirc->ewma;
                dualchan->light_circuit_count += 1;
            }
        }
    }
}

/**
 * Write a cell to a channel_dual_t
 *
 * This implements the write_cell method for channel_dual_t; given a
 * channel_dual_t and a cell_t, transmit the cell_t.
 */

int
channel_dual_write_cell_method(channel_t *chan, cell_t *cell, circuit_t *circ)
{
  channel_dual_t *dualchan = BASE_CHAN_TO_DUAL(chan);

  tor_assert(dualchan);
  tor_assert(cell);

  channel_dual_update_circuit_ewma(dualchan, cell->circ_id);
  channel_dual_circuit_t *dualcirc = channel_dual_find_circuit(dualchan, cell->circ_id);

  if(!dualcirc->writeconn) {
      dualcirc->writeconn = dualchan->lightconn;
  }
  
  log_info(LD_CHANNEL, "write cell %d for circuit %u on %s conn for chan %p", cell->sequence, cell->circ_id, 
          (dualcirc->writeconn == dualchan->lightconn ? "light" : "heavy"), chan);

  connection_or_write_cell_to_buf(cell, dualcirc->writeconn);

  return 1;
}

/**
 * Write a packed cell to a channel_dual_t
 *
 * This implements the write_packed_cell method for channel_dual_t; given a
 * channel_dual_t and a packed_cell_t, transmit the packed_cell_t.
 */


static void
channel_dual_cell_unpack(cell_t *dest, const char *src, int wide_circ_ids)
{
  if (wide_circ_ids) {
    dest->circ_id = ntohl(get_uint32(src));
    src += 4;
  } else {
    dest->circ_id = ntohs(get_uint16(src));
    src += 2;
  }
  dest->sequence = ntohl(get_uint32(src));
  src += 4;
  dest->command = get_uint8(src);
  memcpy(dest->payload, src+1, CELL_PAYLOAD_SIZE);
}

int
channel_dual_write_packed_cell_method(channel_t *chan, or_connection_t *conn,
                                     circuit_t *circ, packed_cell_t *packed_cell)
{
  channel_dual_t *dualchan = BASE_CHAN_TO_DUAL(chan);
  size_t cell_network_size = get_cell_network_size(chan->wide_circ_ids);

  tor_assert(dualchan);
  tor_assert(packed_cell);

  cell_t cell;
  channel_dual_cell_unpack(&cell, packed_cell->body, chan->wide_circ_ids);

  channel_dual_update_circuit_ewma(dualchan, cell.circ_id);
  channel_dual_circuit_t *dualcirc = channel_dual_find_circuit(dualchan, cell.circ_id);

  if(!dualcirc->writeconn) {
      dualcirc->writeconn = dualchan->lightconn;
  }

  log_info(LD_CHANNEL, "write packed cell %d for circuit %u on %s conn (%p) for chan %p", cell.sequence, cell.circ_id, 
          (dualcirc->writeconn == dualchan->lightconn ? "light" : (dualcirc->writeconn == dualchan->heavyconn ? "heavy" : "unknown")), dualcirc->writeconn, chan);

  connection_write_to_buf(packed_cell->body, cell_network_size, TO_CONN(dualcirc->writeconn));

  packed_cell_free(packed_cell);

  return 1;
}

/**
 * Write a variable-length cell to a channel_dual_t
 *
 * This implements the write_var_cell method for channel_dual_t; given a
 * channel_dual_t and a var_cell_t, transmit the var_cell_t.
 */

int
channel_dual_write_var_cell_method(channel_t *chan, var_cell_t *var_cell, circuit_t *circ)
{
  channel_dual_t *dualchan = BASE_CHAN_TO_DUAL(chan);

  tor_assert(dualchan);
  tor_assert(var_cell);

  channel_dual_update_circuit_ewma(dualchan, var_cell->circ_id);
  channel_dual_circuit_t *dualcirc = channel_dual_find_circuit(dualchan, var_cell->circ_id);

  if(!dualcirc->writeconn) {
      dualcirc->writeconn = dualchan->lightconn;
  }
  
  log_info(LD_CHANNEL, "write var cell for circuit %u on %s conn for chan %p", var_cell->circ_id, 
          (dualcirc->writeconn == dualchan->lightconn ? "light" : "heavy"), chan);

  connection_or_write_var_cell_to_buf(var_cell, dualcirc->writeconn);

  return 1;
}

/*******************************************************
 * Functions for handling events on an or_connection_t *
 ******************************************************/

void
channel_dual_handle_state_change_on_orconn(channel_t *chan, or_connection_t *conn,
                                      uint8_t old_state, uint8_t state)
{
  tor_assert(chan);
  tor_assert(conn);
  /* -Werror appeasement */
  tor_assert(old_state == old_state);

  channel_dual_t *dualchan = BASE_CHAN_TO_DUAL(chan);

  /* Make sure the base connection state makes sense - shouldn't be error,
   * closed or listening. */

  tor_assert(chan->state == CHANNEL_STATE_OPENING ||
             chan->state == CHANNEL_STATE_OPEN ||
             chan->state == CHANNEL_STATE_MAINT ||
             chan->state == CHANNEL_STATE_CLOSING);

  if (state == OR_CONN_STATE_OPEN) {
    if(!dualchan->lightconn) {
        dualchan->lightconn = conn;
        log_info(LD_CHANNEL, "channel %p assigning %p as light conn", dualchan, dualchan->lightconn);
    } else if(!dualchan->heavyconn) {
        dualchan->heavyconn = conn;
        log_info(LD_CHANNEL, "channel %p assigning %p as light conn", dualchan, dualchan->heavyconn);
    } else {
        log_warn(LD_CHANNEL, "connection opened when we already have light and heavy connection (conn=%p  light=%p  heavy=%p)",
                conn, dualchan->lightconn, dualchan->heavyconn);
    }

    if(chan->state != CHANNEL_STATE_OPEN) {
        channel_change_state(chan, CHANNEL_STATE_OPEN);
    }

  }
}

static int
channel_dual_compare_cells(const void *_a, const void *_b)
{
	const cell_t *a = _a;
	const cell_t *b = _b;

	if(a->sequence < b->sequence)
		return -1;

	if(a->sequence > b->sequence)
		return 1;

	return 0;
}

static void
channel_dual_flush_circ_queue(channel_dual_circuit_t *circ, or_connection_t *conn)
{
	while(smartlist_len(circ->cell_queue)) {
		channel_dual_cell_t *chan_cell = smartlist_get(circ->cell_queue, 0);

		if(chan_cell->cell.sequence != circ->next_sequence) {
			break;
		}

		channel_tls_handle_cell(&(chan_cell->cell), conn);
		circ->next_sequence += 1;
		smartlist_pqueue_pop(circ->cell_queue, channel_dual_compare_cells,
				STRUCT_OFFSET(channel_dual_cell_t, minheap_idx));
	}
}

void
channel_dual_update_connections(channel_dual_t *dualchan, or_connection_t *readconn, 
															 	channel_dual_circuit_t *dualcirc)
{
	tor_assert(dualchan);
	tor_assert(readconn);

	channel_t *chan = DUAL_CHAN_TO_BASE(dualchan);
	circuit_t *circ = dualcirc->circ;

	dualcirc->readconn = readconn;

	/* if the circuit is an OR circuit, then it's not an edge and we want
	 * to also swap the write connection used instead of rely on EWMA */
	if(CIRCUIT_IS_ORCIRC(circ)) {
		channel_dual_t *next_chan;
		circid_t next_circ_id;

		/* find the "next" channel (will either be n_chan or p_chan depending
		 * if the cell is travelling upstream or downstream */
		if(chan == circ->n_chan) {
			next_chan = BASE_CHAN_TO_DUAL(TO_OR_CIRCUIT(circ)->p_chan);
			next_circ_id = TO_OR_CIRCUIT(circ)->p_circ_id;
		} else if(chan == TO_OR_CIRCUIT(circ)->p_chan) {
			next_chan = BASE_CHAN_TO_DUAL(circ->n_chan);
			next_circ_id = circ->n_circ_id;
		} else {
			log_warn(LD_CHANNEL, "channel matched neither next or previous chan on circ %u", dualcirc->circ_id);
			return;
		}

		if(next_chan) {
			channel_dual_circuit_t *next_circ = channel_dual_find_circuit(next_chan, next_circ_id);    

			if(!next_circ) {
				log_warn(LD_CHANNEL, "unable to find previous circuit %u, defaulting to light conn", next_circ_id);
				return;
			}

			if(readconn == dualchan->lightconn) {
				if(next_circ->writeconn != next_chan->lightconn) {
					log_info(LD_CHANNEL, "switching circuit %u to light connection (%p -> %p)", next_circ_id, next_circ->writeconn, next_chan->lightconn);
					next_circ->writeconn = next_chan->lightconn;
				}
			} else if(readconn == dualchan->heavyconn) {
				if(next_circ->writeconn != next_chan->heavyconn) {
					next_circ->writeconn = next_chan->heavyconn;
					log_info(LD_CHANNEL, "switching circuit %u to heavy connection", next_circ_id);
				}
			} else {
				log_warn(LD_CHANNEL, "read connection on prev circuit doesn't match light or heavy conn");
			}
		}
	}
}

void
channel_dual_handle_cell(cell_t *cell, or_connection_t *conn)
{
  channel_t *chan = conn->chan;
  channel_dual_t *dualchan = BASE_CHAN_TO_DUAL(chan);

  channel_dual_circuit_t *dualcirc = channel_dual_find_circuit(dualchan, cell->circ_id);

  if(!cell->sequence || !dualcirc) {
    log_info(LD_CHANNEL, "processing cell %d right away", cell->sequence);
    channel_tls_handle_cell(cell, conn);
    return;
  }

  log_info(LD_CHANNEL, "received cell %d with command %d on circuit %u on %s conn for chan %p",
          cell->sequence, cell->command, cell->circ_id, 
          (conn == dualchan->lightconn ? "light" : (conn == dualchan->heavyconn ? "heavy" : "unknown")), conn->chan);

  if(conn != dualcirc->readconn) {
      channel_dual_update_connections(dualchan, conn, dualcirc);
  }

  if(!dualcirc->next_sequence) {
      if(cell->sequence != 1) {
          log_info(LD_CHANNEL, "first cell on circuit %u had sequence %u", cell->circ_id, cell->sequence);
      }
      dualcirc->next_sequence = cell->sequence;
  }

  if(cell->sequence == dualcirc->next_sequence) {
    channel_tls_handle_cell(cell, conn);
    dualcirc->next_sequence += 1;

    channel_dual_flush_circ_queue(dualcirc, conn);
  } else {
      log_info(LD_CHANNEL, "received out of order cell %d on circuit %u, was expecting %d", 
              cell->sequence, cell->circ_id, dualcirc->next_sequence);

      channel_dual_cell_t *chan_cell = tor_malloc_zero(sizeof(*chan_cell));
      chan_cell->cell.circ_id = cell->circ_id;
      chan_cell->cell.sequence = cell->sequence;
      chan_cell->cell.command = cell->command;
      memcpy(chan_cell->cell.payload, cell->payload, CELL_PAYLOAD_SIZE);

      smartlist_pqueue_add(dualcirc->cell_queue, channel_dual_compare_cells,
              STRUCT_OFFSET(channel_dual_cell_t, minheap_idx), chan_cell);
  }
}

void
channel_dual_handle_var_cell(var_cell_t *var_cell, or_connection_t *conn)
{
  channel_tls_handle_var_cell(var_cell, conn);
}

void 
channel_dual_add_connection(channel_t *chan, or_connection_t *conn)
{
	tor_assert(chan);
	tor_assert(conn);

	channel_dual_t *dualchan = BASE_CHAN_TO_DUAL(chan);

	(*(dualchan->newconn)) = conn;
}

void 
channel_dual_remove_connection(channel_t *chan, or_connection_t *conn)
{
	tor_assert(chan);
	tor_assert(conn);

	channel_dual_t *dualchan = BASE_CHAN_TO_DUAL(chan);

	smartlist_remove(dualchan->connections, conn);

	if(dualchan->lightconn == conn) {
		log_notice(LD_CHANNEL, "light connection closed on channel %p, creating new one", dualchan);
	} else if(dualchan->heavyconn == conn) {
		log_notice(LD_CHANNEL, "heavy connection closed on channel %p, creating new one", dualchan);
	} else {
		log_notice(LD_CHANNEL, "unknown connection closed on channel %p", dualchan);
		return;
	}

	SMARTLIST_FOREACH_BEGIN(dualchan->circuits, channel_dual_circuit_t *, circ) {
		if(circ->writeconn == conn) {
			circ->writeconn = NULL;
		}
	} SMARTLIST_FOREACH_END(circ);

	or_connection_t *newconn;

	dualchan->newconn = &(newconn);
	newconn = connection_or_connect(&(dualchan->addr), dualchan->port, dualchan->id_digest, chan);

	if (!newconn) {
		log_warn(LD_CHANNEL, "Error creating connection, move to CHANNEL_STATE_ERROR");
		chan->reason_for_closing = CHANNEL_CLOSE_FOR_ERROR;
		channel_change_state(chan, CHANNEL_STATE_ERROR);
		return;
	}

	smartlist_add(dualchan->connections, newconn);
}

void 
channel_dual_add_circuit(channel_t *chan, circuit_t *circ, circid_t circ_id)
{
	tor_assert(chan);
	tor_assert(circ);

	channel_dual_t *dualchan = BASE_CHAN_TO_DUAL(chan);

  channel_dual_circuit_t *dualcirc = channel_dual_find_circuit(dualchan, circ_id);
  if(dualcirc) {
    log_info(LD_CHANNEL, "updating circuit %u to use circuit %p", circ_id, circ);
    dualcirc->circ = circ;
    return;
  }

	log_info(LD_CHANNEL, "adding circuit %u to channel %p (lightconn %p heavyconn %p)", circ_id, dualchan, 
			dualchan->lightconn, dualchan->heavyconn);

	dualcirc = tor_malloc_zero(sizeof(*dualcirc));
	dualcirc->circ = circ;
	dualcirc->circ_id = circ_id;
	dualcirc->status = CIRC_LIGHT;
	dualcirc->readconn = NULL;
	dualcirc->writeconn = NULL;
	dualcirc->cell_queue = smartlist_new();
	smartlist_add(dualchan->circuits, dualcirc);

	dualchan->light_circuit_count += 1;
}

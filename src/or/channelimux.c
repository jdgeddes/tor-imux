/* * Copyright (c) 2012-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file channelimux.c
 * \brief channel_t concrete subclass using or_connection_t
 **/

/*
 * Define this so channel.h gives us things only channel_t subclasses
 * should touch.
 */

#define TOR_CHANNEL_INTERNAL_

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <math.h>

#include "or.h"
#include "channel.h"
#include "channeltls.h"
#include "channelimux.h"
#include "circuitlist.h"
#include "circuitmux.h"
#include "circuitmux_ewma.h"
#include "config.h"
#include "connection.h"
#include "connection_or.h"
#include "control.h"
#include "main.h"
#include "relay.h"
#include "router.h"
#include "routerlist.h"

#define EWMA_TICK 10
#define EWMA_HALFLIFE 66.0
#define LOG_ONEHALF -0.69314718055994529
#define EWMA_ACTIVE_THRESHOLD 50.0

#define IMUX_LOG_LEVEL LOG_INFO

#define IMUXCIRC_TRAFFIC_TYPE(imuxcirc) (!(imuxcirc->circ) ? (TRAFFIC_TYPE_UNKNOWN) : (imuxcirc->circ->traffic_type))

/**************************************
 * Hash table for connection entries
 **************************************/

typedef struct channel_imux_conn_entry_t {
    HT_ENTRY(channel_imux_conn_entry_t) node;
    tor_addr_t addr;
    channel_t *chan;
} channel_imux_conn_entry_t;

/** Map from channel to IP address */
static HT_HEAD(channel_imux_map, channel_imux_conn_entry_t) channel_by_addr =
     HT_INITIALIZER();

/** Hashtable helper: compute a hash of a clientmap_entry_t. */
static INLINE unsigned
channel_imux_map_entry_hash(const channel_imux_conn_entry_t *a)
{
  return ht_improve_hash(tor_addr_hash(&a->addr));
}
/** Hashtable helper: compare two channel_imux_map_entry_t values for equality. */
static INLINE int
channel_imux_map_entry_eq(const channel_imux_conn_entry_t *a, const channel_imux_conn_entry_t *b)
{
  return !tor_addr_compare(&a->addr, &b->addr, CMP_EXACT);
}

HT_PROTOTYPE(channel_imux_map, channel_imux_conn_entry_t, node, channel_imux_map_entry_hash,
             channel_imux_map_entry_eq);
HT_GENERATE(channel_imux_map, channel_imux_conn_entry_t, node, channel_imux_map_entry_hash,
            channel_imux_map_entry_eq, 0.6, malloc, realloc, free);


/* Utility function declarations */
static void channel_imux_common_init(channel_imux_t *imuxchan);

/**
 * Do parts of channel_imux_t initialization common to channel_imux_connect()
 * and channel_imux_handle_incoming().
 */

static void
channel_imux_common_init(channel_imux_t *imuxchan)
{
  channel_t *chan;

  tor_assert(imuxchan);

  chan = &(imuxchan->base_);
  channel_init(chan);
  chan->magic = IMUX_CHAN_MAGIC;
  chan->state = CHANNEL_STATE_OPENING;
  chan->close = channel_imux_close_method;
  chan->describe_transport = channel_imux_describe_transport_method;
  chan->get_remote_addr = channel_imux_get_remote_addr_method;
  chan->get_remote_descr = channel_imux_get_remote_descr_method;
  chan->get_transport_name = channel_imux_get_transport_name_method;
  chan->has_queued_writes = channel_imux_has_queued_writes_method;
  chan->is_canonical = channel_imux_is_canonical_method;
  chan->matches_extend_info = channel_imux_matches_extend_info_method;
  chan->matches_target = channel_imux_matches_target_method;
  chan->write_cell = channel_imux_write_cell_method;
  chan->write_packed_cell = channel_imux_write_packed_cell_method;
  chan->write_var_cell = channel_imux_write_var_cell_method;

  chan->cmux = circuitmux_alloc();
  if (cell_ewma_enabled()) {
    circuitmux_set_policy(chan->cmux, &ewma_policy);
  }

  imuxchan->schedule_type = get_options()->IMUXScheduleType;
}

channel_imux_connection_t *
channel_imux_create_connection(channel_imux_t *imuxchan)
{
    channel_t *chan = IMUX_CHAN_TO_BASE(imuxchan);
    or_connection_t *conn;

    imuxchan->newconn = &(conn);
    conn = connection_or_connect(&(imuxchan->addr), imuxchan->port, imuxchan->id_digest, chan);

    if (!conn) {
        return NULL;
    }

    channel_imux_connection_t *imuxconn = tor_malloc_zero(sizeof(*imuxconn));
    imuxconn->conn = conn;
    imuxconn->ewma.ewma_val = 1;
    imuxconn->create_time = time(NULL);
    smartlist_add(imuxchan->connections, imuxconn);

    return imuxconn;
}

/**
 * Start a new IMUX channel
 *
 * Launch a new OR connection to <b>addr</b>:<b>port</b> and expect to
 * handshake with an OR with identity digest <b>id_digest</b>, and wrap
 * it in a channel_imux_t.
 */

channel_t *
channel_imux_connect(const tor_addr_t *addr, uint16_t port,
                    const char *id_digest)
{
  channel_imux_t *imuxchan = tor_malloc_zero(sizeof(*imuxchan));
  channel_t *chan = &(imuxchan->base_);
  int i;

  channel_imux_common_init(imuxchan);

  log_debug(LD_CHANNEL,
            "In channel_imux_connect() for channel %p "
            "(global id " U64_FORMAT ")",
            imuxchan,
            U64_PRINTF_ARG(chan->global_identifier));

  if (is_local_addr(addr)) channel_mark_local(chan);
  channel_mark_outgoing(chan);

  log_fn(IMUX_LOG_LEVEL, LD_CHANNEL, "channel %p: created channel to %s", imuxchan, fmt_addrport(addr, port));

  imuxchan->addr = *addr;   
  /*imuxchan->port = port;*/
  imuxchan->port = 9111;
  memcpy(imuxchan->id_digest, id_digest, DIGEST_LEN);
  imuxchan->circuits = smartlist_new();
  imuxchan->connections = smartlist_new();
  imuxchan->open_connections = smartlist_new();
  imuxchan->ewma_scale_factor = exp(LOG_ONEHALF / (EWMA_HALFLIFE / EWMA_TICK));
  imuxchan->ewma_last_circuit_scale = 0;
  imuxchan->opening_connections = 1;

  /* figure out how many connections to initally create */
  int n_conns = get_n_open_sockets();
  int total_max_conns = get_options()->ConnLimit_ * get_options()->IMUXConnLimitThreshold;
  int num_connections_to_create = get_options()->IMUXInitConnections;
  if(n_conns >= total_max_conns)
    num_connections_to_create = 1;

  for(i = 0; i < num_connections_to_create; i++) {
    channel_imux_connection_t *imuxconn = channel_imux_create_connection(imuxchan);
    if(!imuxconn)  {
      log_warn(LD_CHANNEL, "channel %p: error creating connection %d, move to CHANNEL_STATE_ERROR", imuxchan, i + 1);
      chan->reason_for_closing = CHANNEL_CLOSE_FOR_ERROR;
      channel_change_state(chan, CHANNEL_STATE_ERROR);
      goto err;
    }

    log_fn(IMUX_LOG_LEVEL, LD_CHANNEL, "channel %p: created connection %d with sock %d on channel id " U64_FORMAT " (imuxconn %p orconn %p)", imuxchan,
        i + 1, TO_CONN(imuxconn->conn)->s, U64_PRINTF_ARG(chan->global_identifier), imuxconn, imuxconn->conn);
  }

  channel_imux_conn_entry_t lookup, *ent;

  tor_addr_copy(&lookup.addr, addr);
  ent = HT_FIND(channel_imux_map, &channel_by_addr, &lookup);

  if(!ent) {
      ent = tor_malloc_zero(sizeof(*ent));
      tor_addr_copy(&(ent->addr), addr);
      ent->chan = chan;
      HT_INSERT(channel_imux_map, &channel_by_addr, ent);
  } else {
      log_info(LD_CHANNEL, "channel %p: already had entry in map for %s", imuxchan, fmt_addr(addr));
  }

  goto done;

 err:
  circuitmux_free(chan->cmux);
  tor_free(imuxchan);
  chan = NULL;

 done:
  /* If we got one, we should register it */
  if (chan) {
    channel_register(chan);
    chan->type = CHANNEL_TYPE_IMUX;
  }

  return chan;
}

channel_imux_connection_t *
channel_imux_get_connection_to_close(channel_imux_t *imuxchan, int consider_open)
{
  tor_assert(imuxchan);

  channel_imux_connection_t *imuxconn = NULL;
  /* pick the newest created connection to close based on whether or not
   * it's open and if it's the bulk connection or not */
  SMARTLIST_FOREACH_BEGIN(imuxchan->connections, channel_imux_connection_t *, c)
  {
    connection_t *conn = TO_CONN(c->conn);
    if((conn->state >= OR_CONN_STATE_MIN_) && 
       (conn->state < OR_CONN_STATE_OR_HANDSHAKING_V3 || consider_open) &&
       (!c->marked_for_close) &&
       (!get_options()->IMUXSeparateBulkConnection || imuxchan->bulk_connection != c)) 
    {
      if(!imuxconn || imuxconn->create_time >= c->create_time)
        imuxconn = c;
    }
  }
  SMARTLIST_FOREACH_END(c);

  return imuxconn;
}


void
channel_imux_send_command_cell(or_connection_t *conn, int command)
{
  cell_t cell;
  memset(&cell,0,sizeof(cell_t));
  cell.command = command;
  connection_or_write_cell_to_buf(&cell, conn);

  connection_start_writing(TO_CONN(conn));
}

void
channel_imux_mark_conn_for_close(channel_imux_t *imuxchan, channel_imux_connection_t *imuxconn)
{
  tor_assert(imuxchan);
  tor_assert(imuxconn);

  SMARTLIST_FOREACH_BEGIN(imuxchan->circuits, channel_imux_circuit_t *, imuxcirc) 
  {
    if(imuxcirc->writeconn == imuxconn) {
      imuxcirc->writeconn = NULL;
    }
  }
  SMARTLIST_FOREACH_END(imuxcirc);

  imuxconn->marked_for_close = 1;
}

void
channel_imux_close_connection(channel_imux_t *imuxchan, channel_imux_connection_t *imuxconn)
{
  tor_assert(imuxchan);
  tor_assert(imuxconn);

  /* write CELL_CLOSING_CONN to buffer then mark connection for closing */
  if(!imuxconn->marked_for_close) {
     channel_imux_send_command_cell(imuxconn->conn, CELL_CLOSING_CONN);
  }

  imuxchan->opening_connections = 1;
  channel_imux_mark_conn_for_close(imuxchan, imuxconn);
  smartlist_remove(imuxchan->open_connections, imuxconn);
  /*connection_or_close_normally(imuxconn->conn, 1);*/
}


/**
 * Create a new channel around an incoming or_connection_t
 */

channel_t *
channel_imux_create_incoming(tor_addr_t addr, uint16_t port, char *id_digest)
{
  channel_imux_t *imuxchan = tor_malloc_zero(sizeof(*imuxchan));
  channel_t *chan = &(imuxchan->base_);
  chan->type = CHANNEL_TYPE_IMUX;

  channel_imux_common_init(imuxchan);

  log_fn(IMUX_LOG_LEVEL, LD_CHANNEL, "channel %p: creating incoming channel from %s", imuxchan, fmt_addrport(&addr, port));

  imuxchan->addr = addr;
  /*imuxchan->port = port;*/
  imuxchan->port = 9111;
  memcpy(imuxchan->id_digest, id_digest, DIGEST_LEN);
  imuxchan->circuits = smartlist_new();
  imuxchan->connections = smartlist_new();
  imuxchan->open_connections = smartlist_new();
  imuxchan->ewma_scale_factor = exp(LOG_ONEHALF / (EWMA_HALFLIFE / EWMA_TICK));
  imuxchan->ewma_last_circuit_scale = 0;
  imuxchan->opening_connections = 0;

  if (is_local_addr(&addr)) channel_mark_local(chan);
  channel_mark_incoming(chan);

  /* If we got one, we should register it */
  if (chan) {
      channel_register(chan);
  }

  return chan;
}

channel_t *
channel_imux_handle_incoming(or_connection_t *orconn)
{
  tor_assert(orconn);
  tor_assert(!(orconn->chan));

  tor_addr_t addr = TO_CONN(orconn)->addr;
  uint16_t port = TO_CONN(orconn)->port;
  char *id_digest = orconn->identity_digest;

  channel_imux_conn_entry_t lookup, *ent;

  tor_addr_copy(&lookup.addr, &(addr));
  ent = HT_FIND(channel_imux_map, &channel_by_addr, &lookup);

  if(!ent) {
      ent = tor_malloc_zero(sizeof(*ent));
      tor_addr_copy(&(ent->addr), &(addr));
      ent->chan = channel_imux_create_incoming(addr, port, id_digest);
      HT_INSERT(channel_imux_map, &channel_by_addr, ent);
  }

  channel_t *chan = ent->chan;
  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);
  channel_imux_connection_t *imuxconn = NULL;
  orconn->chan = chan;

  /*int n_conns = get_n_open_sockets();*/
  /*int total_max_conns = (get_options()->ConnLimit_ - 32) * get_options()->IMUXConnLimitThreshold;*/

  int channel_n_conns = smartlist_len(imuxchan->connections) + 1;
  int channel_max_conns = channel_imux_get_chan_max_connections(imuxchan);

  /* if we have too many connections open, the other relay is opening too many and pick one to close,
   * notifying the relay that we have enough open connections */
  if(channel_n_conns >= channel_max_conns && smartlist_len(imuxchan->connections) > get_options()->IMUXInitConnections) {
    log_fn(IMUX_LOG_LEVEL, LD_CHANNEL, "channel %p: (incoming) we have %d connections with maxconns %d (%d open), closing conn %p with socket %d", imuxchan,
        channel_n_conns, channel_max_conns, smartlist_len(imuxchan->open_connections), orconn, TO_CONN(orconn)->s);

    /* try and find a non-open conneciton to close first */
    imuxconn = channel_imux_get_connection_to_close(imuxchan, 0);
    if(!imuxconn && smartlist_len(imuxchan->open_connections) > get_options()->IMUXInitConnections)
      imuxconn = channel_imux_get_connection_to_close(imuxchan, 1);

    if(imuxconn) {
      log_fn(IMUX_LOG_LEVEL, LD_CHANNEL, "channel %p: (incoming) closing connection %p with socket %d and state %d", imuxchan, imuxconn, 
          TO_CONN(imuxconn->conn)->s, TO_CONN(imuxconn->conn)->state);

      channel_imux_close_connection(imuxchan, imuxconn);
    }
  }

  imuxconn = tor_malloc_zero(sizeof(*imuxconn));
  imuxconn->conn = orconn;
  imuxconn->ewma.ewma_val = 1;
  imuxconn->create_time = time(NULL);
  smartlist_add(imuxchan->connections, imuxconn);

  log_fn(IMUX_LOG_LEVEL, LD_CHANNEL, "channel %p: accepting incoming conneciton %p orconn %p (socket %d) from %s (incoming %s)", imuxchan, imuxconn, orconn,
      TO_CONN(orconn)->s, fmt_addrport(&(TO_CONN(orconn)->addr), TO_CONN(orconn)->port), fmt_addrport(&imuxchan->addr, imuxchan->port));

  return chan;
}

/*********
 * Casts *
 ********/

/**
 * Cast a channel_imux_t to a channel_t.
 */

channel_t *
channel_imux_to_base(channel_imux_t *imuxchan)
{
  if (!imuxchan) return NULL;

  return &(imuxchan->base_);
}

/**
 * Cast a channel_t to a channel_imux_t, with appropriate type-checking
 * asserts.
 */

channel_imux_t *
channel_imux_from_base(channel_t *chan)
{
  if (!chan) return NULL;

  tor_assert(chan->magic == IMUX_CHAN_MAGIC);

  return (channel_imux_t *)(chan);
}

/********************************************
 * Method implementations for channel_imux_t *
 *******************************************/

/**
 * Close a channel_imux_t
 *
 * This implements the close method for channel_imux_t
 */

void
channel_imux_close_method(channel_t *chan)
{
  tor_assert(chan);
  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

  log_fn(IMUX_LOG_LEVEL, LD_CHANNEL, "channel %p: closing IMUX channel", imuxchan);

  if(smartlist_len(imuxchan->open_connections) > 0) {
    channel_imux_connection_t *imuxconn = smartlist_get(imuxchan->open_connections, 0);
    cell_t cell;
    memset(&cell,0,sizeof(cell_t));
    cell.command = CELL_CLOSING_CHAN;
    connection_or_write_cell_to_buf(&cell, imuxconn->conn);
  }

  SMARTLIST_FOREACH_BEGIN(imuxchan->connections, channel_imux_connection_t *, c) 
  {
    connection_or_close_normally(c->conn, 1);
  }
  SMARTLIST_FOREACH_END(c);

  /* remove channel from incoming list if there */
  channel_imux_conn_entry_t lookup, *ent;
  tor_addr_copy(&lookup.addr, &(imuxchan->addr));
  ent = HT_REMOVE(channel_imux_map, &channel_by_addr, &lookup);
  if(ent)
    tor_free(ent);
}

/**
 * Describe the transport for a channel_imux_t
 *
 * This returns the string "IMUX channel on connection <id>" to the upper
 * layer.
 */

const char *
channel_imux_describe_transport_method(channel_t *chan)
{
  char *buf = NULL;
  uint64_t id;
  channel_imux_t *imuxchan;
  const char *rv = NULL;

  tor_assert(chan);

  imuxchan = BASE_CHAN_TO_IMUX(chan);

  if(smartlist_len(imuxchan->connections) > 0) 
  {
    channel_imux_connection_t *imuxconn = smartlist_get(imuxchan->connections, 0); 
    or_connection_t *conn = imuxconn->conn;
    id = TO_CONN(conn)->global_identifier;

    if (buf) tor_free(buf);
    tor_asprintf(&buf,
                 "IMUX channel (connection " U64_FORMAT ")",
                 U64_PRINTF_ARG(id));

    rv = buf;
  } else {
    rv = "IMUX channel (no connection)";
  }

  return rv;
}

/**
 * Get the name of the pluggable transport used by a channel_dual_t.
 *
 * This implements the get_transport_name for channel_dual_t. If the
 * channel uses a pluggable transport, copy its name to
 * <b>transport_out</b> and return 0. If the channel did not use a
 * pluggable transport, return -1. */

int
channel_imux_get_transport_name_method(channel_t *chan, char **transport_out)
{
  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

  tor_assert(imuxchan);
  tor_assert(transport_out);
  tor_assert(smartlist_len(imuxchan->connections));

  channel_imux_connection_t *imuxconn = (channel_imux_connection_t *)smartlist_get(imuxchan->connections, 0);
  or_connection_t *conn = imuxconn->conn;

  if (!conn->ext_or_transport)
    return -1;

  *transport_out = tor_strdup(conn->ext_or_transport);
  return 0;
}

/**
 * Get the remote address of a channel_imux_t
 *
 * This implements the get_remote_addr method for channel_imux_t; copy the
 * remote endpoint of the channel to addr_out and return 1 (always
 * succeeds for this transport).
 */

int
channel_imux_get_remote_addr_method(channel_t *chan, tor_addr_t *addr_out)
{
  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

  tor_assert(imuxchan);
  tor_assert(addr_out);

  tor_addr_copy(addr_out, &imuxchan->addr);

  return 1;
}

/**
 * Get endpoint description of a channel_imux_t
 *
 * This implements the get_remote_descr method for channel_imux_t; it returns
 * a text description of the remote endpoint of the channel suitable for use
 * in log messages.  The req parameter is 0 for the canonical address or 1 for
 * the actual address seen.
 */

const char *
channel_imux_get_remote_descr_method(channel_t *chan, int flags)
{
#define MAX_DESCR_LEN 32

  char buf[MAX_DESCR_LEN + 1];
  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);
  const char *answer = NULL;
  char *addr_str;

  tor_assert(imuxchan);

  addr_str = tor_dup_addr(&(imuxchan->addr));
  uint16_t port = imuxchan->port;

  switch (flags) {
    case 0:
      /* Canonical address with port*/
      tor_snprintf(buf, MAX_DESCR_LEN + 1,
                   "%s:%u", addr_str, port);
      answer = buf;
      break;
    case GRD_FLAG_ORIGINAL:
      /* Actual address with port */
      tor_snprintf(buf, MAX_DESCR_LEN + 1,
                   "%s:%u", addr_str, port);
      answer = buf;
      break;
    case GRD_FLAG_ADDR_ONLY:
      /* Canonical address, no port */
      strlcpy(buf, addr_str, sizeof(buf));
      answer = buf;
      break;
    case GRD_FLAG_ORIGINAL|GRD_FLAG_ADDR_ONLY:
      /* Actual address, no port */
      strlcpy(buf, addr_str, sizeof(buf));
      answer = buf;
      break;

    default:
      /* Something's broken in channel.c */
      tor_assert(1);
  }

  tor_free(addr_str);

  return answer;
}

/**
 * Tell the upper layer if we have queued writes
 *
 * This implements the has_queued_writes method for channel_imux t_; it returns
 * 1 iff we have queued writes on the outbuf of the underlying or_connection_t.
 */

int
channel_imux_has_queued_writes_method(channel_t *chan)
{
  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

  tor_assert(imuxchan);

  SMARTLIST_FOREACH_BEGIN(imuxchan->connections, channel_imux_connection_t *, c)
  {
    or_connection_t *conn = c->conn;
    if(connection_get_outbuf_len(TO_CONN(conn)) > 0) 
      return 1;
  }
  SMARTLIST_FOREACH_END(c);

  return 0;
}

/**
 * Tell the upper layer if we're canonical
 *
 * This implements the is_canonical method for channel_imux_t; if req is zero,
 * it returns whether this is a canonical channel, and if it is one it returns
 * whether that can be relied upon.
 */

int
channel_imux_is_canonical_method(channel_t *chan, int req)
{
  int answer = 0;
  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

  tor_assert(imuxchan);

  switch (req) {
    case 0:
      answer = imuxchan->is_canonical;
      break;
    case 1:
      /*
       * Is the is_canonical bit reliable?  In protocols version 2 and up
       * we get the canonical address from a NETINFO cell, but in older
       * versions it might be based on an obsolete descriptor.
       */
      answer = (imuxchan->link_proto >= 2);
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
 * This implements the matches_extend_info method for channel_imux_t; the upper
 * layer wants to know if this channel matches an extend_info_t.
 */

int
channel_imux_matches_extend_info_method(channel_t *chan,
                                       extend_info_t *extend_info)
{
  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

  tor_assert(imuxchan);
  tor_assert(extend_info);

  log_info(LD_CHANNEL, "channel %p: channel %s extend info %s", imuxchan,
          fmt_addrport(&imuxchan->addr, imuxchan->port),
          fmt_addrport(&extend_info->addr, extend_info->port));

  if(tor_addr_eq(&(extend_info->addr), &(imuxchan->addr)) &&
    extend_info->port == imuxchan->port) {
      return 1;
  }

  return 0;
}

/**
 * Check if we match a target address; return true iff we do.
 *
 * This implements the matches_target method for channel_imux t_; the upper
 * layer wants to know if this channel matches a target address when extending
 * a circuit.
 */

int
channel_imux_matches_target_method(channel_t *chan,
                                  const tor_addr_t *target)
{
  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

  tor_assert(imuxchan);
  tor_assert(target);

  return tor_addr_eq(&(imuxchan->addr), target);
}

channel_imux_circuit_t *
channel_imux_find_circuit(channel_imux_t *imuxchan, circid_t circ_id)
{
  tor_assert(imuxchan);

  SMARTLIST_FOREACH_BEGIN(imuxchan->circuits, channel_imux_circuit_t *, c)
  {
    if(c->circ_id == circ_id)
      return c;
  }
  SMARTLIST_FOREACH_END(c);

  return NULL;
}

channel_imux_connection_t *
channel_imux_find_connection_by_orconn(channel_imux_t *imuxchan, or_connection_t *orconn)
{
  tor_assert(imuxchan);

  SMARTLIST_FOREACH_BEGIN(imuxchan->connections, channel_imux_connection_t *, c)
  {
    if(c->conn == orconn)
      return c;
  }
  SMARTLIST_FOREACH_END(c);

  return NULL;
}

channel_imux_connection_t *
channel_imux_get_most_idle_connection(channel_imux_t *imuxchan)
{
  tor_assert(imuxchan);

  channel_imux_connection_t *conn = NULL;
  SMARTLIST_FOREACH_BEGIN(imuxchan->connections, channel_imux_connection_t *, c)
  {
    or_connection_t *orconn = c->conn;
    if(TO_CONN(orconn)->state == OR_CONN_STATE_OPEN && 
        !c->marked_for_close &&
        (!conn || conn->last_active > c->last_active)) 
    {
      conn = c;
    }
  }
  SMARTLIST_FOREACH_END(c);

  return conn;
}

channel_imux_connection_t *
channel_imux_get_next_open_connection(channel_imux_t *imuxchan)
{
  tor_assert(imuxchan);

  if(smartlist_len(imuxchan->open_connections) == 0)
  {
    log_warn(LD_CHANNEL, "channel %p: there are 0 open connections out of %d connections", imuxchan, smartlist_len(imuxchan->connections));
    return NULL;
  }

  tor_assert(smartlist_len(imuxchan->open_connections));

  channel_imux_connection_t *imuxconn = smartlist_get(imuxchan->open_connections, 0);

  smartlist_remove(imuxchan->open_connections, imuxconn);
  smartlist_add(imuxchan->open_connections, imuxconn);

  return imuxconn;
}

channel_imux_connection_t *
channel_imux_get_best_connection(channel_imux_t *imuxchan, channel_imux_circuit_t *imuxcirc)
{
  tor_assert(imuxchan);

  channel_imux_connection_t *bestconn = NULL;
  int conn_queue_size = 0;

  /* if there's only one open connection, just return that */
  if(smartlist_len(imuxchan->open_connections) == 1)
    return smartlist_get(imuxchan->open_connections, 0);

  SMARTLIST_FOREACH_BEGIN(imuxchan->connections, channel_imux_connection_t *, c)
  {
    or_connection_t *conn = c->conn;
    if(TO_CONN(conn)->state == OR_CONN_STATE_OPEN && !c->marked_for_close && c != imuxchan->bulk_connection)
    {
      int queue_size;
      ioctl(TO_CONN(conn)->s, TIOCOUTQ, &queue_size);
      queue_size += connection_get_outbuf_len(TO_CONN(conn));

      if(!bestconn || queue_size < conn_queue_size)
      {
        bestconn = c;
        conn_queue_size = queue_size;
      }
    }
  }
  SMARTLIST_FOREACH_END(c);

  return bestconn;
}

static int
channel_imux_compare_connection_by_ewma(const void **a, const void **b)
{
  channel_imux_connection_t *conn1 = *(channel_imux_connection_t **)a;
  channel_imux_connection_t *conn2 = *(channel_imux_connection_t **)b;

  if(conn1->ewma.ewma_val < conn2->ewma.ewma_val) {
    return -1;
  } else if(conn1->ewma.ewma_val > conn2->ewma.ewma_val) {
    return 1;
  }

  return 0;
}


channel_imux_connection_t *
channel_imux_get_ewma_connection(channel_imux_t *imuxchan, channel_imux_circuit_t *imuxcirc)
{
  tor_assert(imuxchan);
  tor_assert(imuxcirc);

  int circuit_rank = 0;
  int num_active_circuits = 0;

  /* get the rank of the circuit compared to all others */
  SMARTLIST_FOREACH_BEGIN(imuxchan->circuits, channel_imux_circuit_t *, c)
  {
    if(c->active)
    {
      if(c->circ_id != imuxcirc->circ_id && c->ewma.ewma_val < imuxcirc->ewma.ewma_val)
        circuit_rank++;

      num_active_circuits++;
    }
  }
  SMARTLIST_FOREACH_END(c);

  double circuit_percentile = 0;
  if(num_active_circuits > 0)
    circuit_percentile = (double)circuit_rank / (double)num_active_circuits;

  smartlist_t *open_connections = smartlist_new();
  smartlist_sort(imuxchan->connections, channel_imux_compare_connection_by_ewma);
  /* find the equivalent connection that matches the percentile of the circuit */
  SMARTLIST_FOREACH_BEGIN(imuxchan->connections, channel_imux_connection_t *, c)
  {
    if(TO_CONN(c->conn)->state == OR_CONN_STATE_OPEN && !c->marked_for_close)
    {
      smartlist_add(open_connections, c);
    }
  }
  SMARTLIST_FOREACH_END(c);

  int num_connections = smartlist_len(open_connections);
  if(num_connections == 0) {
    return NULL;
  }

  int connection_index = (int)(num_connections * circuit_percentile);
  if(connection_index == num_connections) {
    connection_index -= 1;
  }

  channel_imux_connection_t *imuxconn = smartlist_get(open_connections, connection_index);

  return imuxconn;
}

channel_imux_connection_t *
channel_imux_get_pctcp_connection(channel_imux_t *imuxchan, channel_imux_circuit_t *imuxcirc)
{
  tor_assert(imuxchan);
  tor_assert(imuxcirc);

  if(imuxcirc->writeconn) {
    return imuxcirc->writeconn;
  }

  channel_imux_connection_t *imuxconn = NULL;
  int conn_queue_size = 0;

  SMARTLIST_FOREACH_BEGIN(imuxchan->connections, channel_imux_connection_t *, c)
  {
    or_connection_t *conn = c->conn;
    if(TO_CONN(conn)->state == OR_CONN_STATE_OPEN && !c->marked_for_close && !c->in_use)
    {
      int queue_size;
      ioctl(TO_CONN(conn)->s, TIOCOUTQ, &queue_size);
      queue_size += connection_get_outbuf_len(TO_CONN(conn));

      if(!imuxconn || queue_size < conn_queue_size)
      {
        imuxconn = c;
        conn_queue_size = queue_size;
      }
    }
  }
  SMARTLIST_FOREACH_END(c);

  if(imuxconn)
  {
    imuxcirc->writeconn = imuxconn;
    imuxconn->in_use = 1;
    return imuxconn;
  }

  return channel_imux_get_best_connection(imuxchan, imuxcirc);
}

channel_imux_connection_t *
channel_imux_get_single_web_connection(channel_imux_t *imuxchan, channel_imux_circuit_t *imuxcirc)
{
  tor_assert(imuxchan);
  tor_assert(imuxcirc);

  if(imuxcirc->writeconn)
    return imuxcirc->writeconn;

  if(imuxcirc->circ && imuxcirc->circ->traffic_type == TRAFFIC_TYPE_BULK && imuxchan->bulk_connection) 
  {
    imuxcirc->writeconn = imuxchan->bulk_connection;
    int traffic_type = -1;
    if(imuxcirc->circ) {
      traffic_type = imuxcirc->circ->traffic_type;
    }
    log_info(LD_CHANNEL, "channel %p assigning bulk connection %p to circuit %u with traffic type %d", imuxchan, imuxchan->bulk_connection, imuxcirc->circ_id, traffic_type);
    return imuxcirc->writeconn;
  }

  if(imuxcirc->circ && imuxcirc->circ->traffic_type != TRAFFIC_TYPE_WEB)
    return channel_imux_get_next_open_connection(imuxchan);

  channel_imux_connection_t *imuxconn = NULL;
  int conn_queue_size = 0;

  SMARTLIST_FOREACH_BEGIN(imuxchan->connections, channel_imux_connection_t *, c)
  {
    or_connection_t *conn = c->conn;
    if(TO_CONN(conn)->state == OR_CONN_STATE_OPEN && !c->marked_for_close && !c->in_use && c != imuxchan->bulk_connection)
    {
      int queue_size;
      ioctl(TO_CONN(conn)->s, TIOCOUTQ, &queue_size);
      queue_size += connection_get_outbuf_len(TO_CONN(conn));

      if(!imuxconn || queue_size < conn_queue_size)
      {
        imuxconn = c;
        conn_queue_size = queue_size;
      }
    }
  }
  SMARTLIST_FOREACH_END(c);

  if(imuxconn) 
  {
    int traffic_type = -1;
    if(imuxcirc->circ) {
      traffic_type = imuxcirc->circ->traffic_type;
    }
    log_info(LD_CHANNEL, "channel %p: assigning connection %p to circuit %u with traffic type %d", imuxchan, imuxconn, imuxcirc->circ_id, traffic_type);
    imuxcirc->writeconn = imuxconn;
    imuxconn->in_use = 1;
    return imuxconn;
  }

  /* if we couldn't find a suitable connection (i.e. no traffic type), just return the best one */
  return channel_imux_get_best_connection(imuxchan, imuxcirc);
}



channel_imux_connection_t *
channel_imux_get_write_connection(channel_imux_t *imuxchan, channel_imux_circuit_t *imuxcirc, uint8_t command)
{
  tor_assert(imuxchan);

  channel_imux_connection_t *conn = NULL;

  if(get_options()->IMUXSeparateBulkConnection && imuxcirc && imuxcirc->circ && 
      imuxcirc->circ->traffic_type == TRAFFIC_TYPE_BULK && imuxchan->bulk_connection) {
    return imuxchan->bulk_connection;
  }

  if(get_options()->IMUXSeparateWebConnection && imuxcirc && imuxcirc->circ && 
      imuxcirc->circ->traffic_type == TRAFFIC_TYPE_WEB && imuxchan->web_connection) {
    return imuxchan->web_connection;
  }

  switch(imuxchan->schedule_type)
  {
    case CHANNEL_IMUX_SCHEDULE_RR_CIRC:
      if(!imuxcirc->writeconn)
        imuxcirc->writeconn = channel_imux_get_next_open_connection(imuxchan);
      conn = imuxcirc->writeconn;
      break;

    case CHANNEL_IMUX_SCHEDULE_RR_CELL:
      conn = channel_imux_get_next_open_connection(imuxchan);
      break;

    case CHANNEL_IMUX_SCHEDULE_BEST_SOCKET:
      conn = channel_imux_get_best_connection(imuxchan, imuxcirc);
      break;

    case CHANNEL_IMUX_SCHEDULE_EWMA:
      conn = channel_imux_get_ewma_connection(imuxchan, imuxcirc);
      break;

    case CHANNEL_IMUX_SCHEDULE_PCTCP:
      conn = channel_imux_get_pctcp_connection(imuxchan, imuxcirc);
      break;

    case CHANNEL_IMUX_SCHEDULE_SINGLE_WEB:
      conn = channel_imux_get_single_web_connection(imuxchan, imuxcirc);
      break;

    case CHANNEL_IMUX_SCHEDULE_KIST:
      conn = channel_imux_get_best_connection(imuxchan, imuxcirc);
      break;

    default:
      log_warn(LD_CHANNEL, "unknown IMUX channel scheduler type %d", imuxchan->schedule_type);
  }

  return conn;
}

unsigned int
channel_imux_get_tick(struct timeval *now, double *fractional_tick)
{
  unsigned int tick = now->tv_sec / EWMA_TICK;
  *fractional_tick = ((now->tv_sec % EWMA_TICK) + (now->tv_usec / 1.0e6)) / EWMA_TICK;
  return tick;
}

double
channel_imux_get_scale_factor(unsigned int last_tick, unsigned int curr_tick, double base_scale_factor)
{
  int delta = (int)(curr_tick - last_tick);
  double factor = pow(base_scale_factor, delta);
  return factor;
}

void
channel_imux_circuit_active_check(channel_imux_t *imuxchan, channel_imux_circuit_t *circ)
{
  tor_assert(imuxchan);
  tor_assert(circ);

  channel_t *chan = IMUX_CHAN_TO_BASE(imuxchan);

  /* check the ewma value to see if the circuit is active/inactive */
  if(!circ->active && circ->ewma.ewma_val >= EWMA_ACTIVE_THRESHOLD) 
  {
    circ->active = 1;
    imuxchan->num_active_circuits += 1;
    log_info(LD_CHANNEL, "channel %p: making circuit %u active with ewma %f, %d total active circuits, %d connections", chan, 
        circ->circ_id, circ->ewma.ewma_val, imuxchan->num_active_circuits, smartlist_len(imuxchan->connections));
  } 
  else if(circ->active && circ->ewma.ewma_val < EWMA_ACTIVE_THRESHOLD) 
  {
    circ->active = 0;
    imuxchan->num_active_circuits -= 1;
    log_info(LD_CHANNEL, "channel %p: making circuit %u inactive with ewma %f, %d total active circuits, %d connections", chan, 
        circ->circ_id, circ->ewma.ewma_val, imuxchan->num_active_circuits, smartlist_len(imuxchan->connections));
  }
}

void
channel_imux_update_circuit_ewma(channel_imux_t *imuxchan, channel_imux_circuit_t *circ)
{
  tor_assert(imuxchan);
  tor_assert(circ);

  struct timeval now;
  tor_gettimeofday(&now);

  double scale_factor;
  double fractional_tick;
  unsigned int curr_tick = channel_imux_get_tick(&now, &fractional_tick);

  if(curr_tick != imuxchan->ewma_last_circuit_scale) {
    scale_factor = channel_imux_get_scale_factor(imuxchan->ewma_last_circuit_scale, curr_tick, imuxchan->ewma_scale_factor);

    SMARTLIST_FOREACH_BEGIN(imuxchan->circuits, channel_imux_circuit_t *, c) {
      c->ewma.ewma_val *= scale_factor;
      c->ewma.last_scale = curr_tick;
      channel_imux_circuit_active_check(imuxchan, c);
    } SMARTLIST_FOREACH_END(c);

    imuxchan->ewma_last_circuit_scale = curr_tick;
  }

  double ewma_increment = pow(imuxchan->ewma_scale_factor, -fractional_tick);
  circ->ewma.ewma_val += ewma_increment;

  scale_factor = channel_imux_get_scale_factor(circ->ewma.last_scale, curr_tick, imuxchan->ewma_scale_factor);
  circ->ewma.ewma_val *= scale_factor;
  circ->ewma.last_scale = curr_tick;
  channel_imux_circuit_active_check(imuxchan, circ);
}

void
channel_imux_update_connection_ewma(channel_imux_t *imuxchan, channel_imux_connection_t *imuxconn)
{
  tor_assert(imuxchan);
  tor_assert(imuxconn);

  struct timeval now;
  tor_gettimeofday_cached(&now);

  double scale_factor;
  double fractional_tick;
  unsigned int curr_tick = channel_imux_get_tick(&now, &fractional_tick);

  if(curr_tick != imuxchan->ewma_last_connection_scale) {
    scale_factor = channel_imux_get_scale_factor(imuxchan->ewma_last_connection_scale, curr_tick, imuxchan->ewma_scale_factor);

    SMARTLIST_FOREACH_BEGIN(imuxchan->connections, channel_imux_connection_t *, c) {
      c->ewma.ewma_val *= scale_factor;
      c->ewma.last_scale = curr_tick;
    } SMARTLIST_FOREACH_END(c);

    imuxchan->ewma_last_connection_scale = curr_tick;
  }

  double ewma_increment = pow(imuxchan->ewma_scale_factor, -fractional_tick);
  imuxconn->ewma.ewma_val += ewma_increment;

  scale_factor = channel_imux_get_scale_factor(imuxconn->ewma.last_scale, curr_tick, imuxchan->ewma_scale_factor);
  imuxconn->ewma.ewma_val *= scale_factor;
  imuxconn->ewma.last_scale = curr_tick;
}


/**
 * Write a cell to a channel_imux_t
 *
 * This implements the write_cell method for channel_imux_t; given a
 * channel_imux_t and a cell_t, transmit the cell_t.
 */

int
channel_imux_write_cell_method(channel_t *chan, cell_t *cell, circuit_t *circ)
{
  tor_assert(chan);
  tor_assert(cell);

  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

  channel_imux_circuit_t *imuxcirc = channel_imux_find_circuit(imuxchan, cell->circ_id);
  if(imuxcirc)
    channel_imux_update_circuit_ewma(imuxchan, imuxcirc);

  channel_imux_connection_t *imuxconn = channel_imux_get_write_connection(imuxchan, imuxcirc, cell->command);

  if(!imuxconn) {
    log_warn(LD_CHANNEL, "channel %p: could not find connection to schedule cell %d on circuit %u (%d connections)", imuxchan, 
        cell->sequence, cell->circ_id, smartlist_len(imuxchan->connections));
    return 0;
  }
  
  or_connection_t *conn = imuxconn->conn;
  log_info(LD_CHANNEL, "channel %p: write cell %d (%d) for circuit %u on conn %p", imuxchan, cell->sequence, cell->command, cell->circ_id, conn);

  connection_or_write_cell_to_buf(cell, conn);
  channel_imux_update_connection_ewma(imuxchan, imuxconn);
  imuxconn->last_write = time(NULL);
  imuxconn->last_active = time(NULL);

  imuxcirc->cells_written += 1;

  return 1;
}

/**
 * Write a packed cell to a channel_imux_t
 *
 * This implements the write_packed_cell method for channel_imux_t; given a
 * channel_imux_t and a packed_cell_t, transmit the packed_cell_t.
 */


static void
channel_imux_cell_unpack(cell_t *dest, const char *src, int wide_circ_ids)
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
channel_imux_write_packed_cell_method(channel_t *chan, or_connection_t *conn,
                                     circuit_t *circ, packed_cell_t *packed_cell)
{
  tor_assert(chan);
  tor_assert(packed_cell);

  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

  cell_t cell;
  channel_imux_cell_unpack(&cell, packed_cell->body, chan->wide_circ_ids);

  relay_header_t rh;
  relay_header_unpack(&rh, cell.payload);

  channel_imux_connection_t *imuxconn = channel_imux_find_connection_by_orconn(imuxchan, conn);
  channel_imux_circuit_t *imuxcirc = channel_imux_find_circuit(imuxchan, cell.circ_id);

  if(!imuxcirc)
    imuxcirc = channel_imux_add_circuit(chan, circ, cell.circ_id);
  
  channel_imux_update_circuit_ewma(imuxchan, imuxcirc);

  if(imuxchan->schedule_type != CHANNEL_IMUX_SCHEDULE_KIST || !imuxconn || imuxconn->marked_for_close || TO_CONN(imuxconn->conn)->state != OR_CONN_STATE_OPEN) {
    double ewma_val = 0;
    imuxconn = channel_imux_get_write_connection(imuxchan, imuxcirc, cell.command);
    imuxcirc->cells_written += 1;
    ewma_val = imuxcirc->ewma.ewma_val;

    if(!imuxconn && imuxchan->bulk_connection)  {
      imuxconn = imuxchan->bulk_connection;
      log_info(LD_CHANNEL, "channel %p: could not find an open connection, using bulk connection %p", imuxchan, imuxconn);
    }

    if(!imuxconn) {
        log_warn(LD_CHANNEL, "channel %p: imuxconn is NULL with %d connections (%d open) -- cell %d command %d circuit %u", imuxchan, 
            smartlist_len(imuxchan->connections), smartlist_len(imuxchan->open_connections), cell.sequence, cell.command, cell.circ_id);

        return 0;
    }

    conn = imuxconn->conn;
    log_info(LD_CHANNEL, "channel %p: write packed cell %d with command %d for circuit %u (ewma %f) on conn %p (%p)", imuxchan,
        cell.sequence, cell.command, cell.circ_id, ewma_val, conn, imuxconn);
  } else {
    /* if we are using a separate bulk connection, attempt to use that for bulk traffic circuits */
    if(get_options()->IMUXSeparateBulkConnection && imuxcirc && imuxcirc->circ &&
        imuxcirc->circ->traffic_type == TRAFFIC_TYPE_BULK && imuxchan->bulk_connection)
    {
      imuxconn = imuxchan->bulk_connection;
      conn = imuxconn->conn;
    }

    log_info(LD_CHANNEL, "channel %p: write packed cell %d with command %d for circuit %u (ewma %f) on conn %p (%p) (KIST)", imuxchan,
        cell.sequence, cell.command, cell.circ_id, imuxcirc->ewma.ewma_val, conn, imuxconn);
  }

  size_t cell_network_size = get_cell_network_size(chan->wide_circ_ids);
  connection_write_to_buf(packed_cell->body, cell_network_size, TO_CONN(conn));
  if(imuxconn)
     channel_imux_update_connection_ewma(imuxchan, imuxconn);

  packed_cell_free(packed_cell);

  return 1;
}

/**
 * Write a variable-length cell to a channel_imux_t
 *
 * This implements the write_var_cell method for channel_imux_t; given a
 * channel_imux_t and a var_cell_t, transmit the var_cell_t.
 */

int
channel_imux_write_var_cell_method(channel_t *chan, var_cell_t *var_cell, circuit_t *circ)
{
  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

  tor_assert(imuxchan);
  tor_assert(var_cell);

  channel_imux_circuit_t *imuxcirc = channel_imux_find_circuit(imuxchan, var_cell->circ_id);
  if(imuxcirc)
    channel_imux_update_circuit_ewma(imuxchan, imuxcirc);

  channel_imux_connection_t *imuxconn = channel_imux_get_write_connection(imuxchan, imuxcirc, var_cell->command);
  if(!imuxconn) 
  {
      log_warn(LD_CHANNEL, "channel %p: could not find connection to schedule cell on circuit %u (%d connections)", imuxchan,
          var_cell->circ_id, smartlist_len(imuxchan->connections));
      return 0;
  }

  or_connection_t *conn = imuxconn->conn;
  log_info(LD_CHANNEL, "channel %p: write var cell for circuit %u on conn %p", imuxchan, var_cell->circ_id, conn);

  connection_or_write_var_cell_to_buf(var_cell, conn);
  channel_imux_update_connection_ewma(imuxchan, imuxconn);
  imuxconn->last_write = time(NULL);
  imuxconn->last_active = time(NULL);

  imuxcirc->cells_written += 1;

  return 1;
}

/*******************************************************
 * Functions for handling events on an or_connection_t *
 ******************************************************/

channel_imux_connection_t *
channel_imux_find_imux_connection(channel_t *chan, or_connection_t *conn)
{
  tor_assert(chan);
  tor_assert(conn);

  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

  SMARTLIST_FOREACH_BEGIN(imuxchan->connections, channel_imux_connection_t *, imuxconn)
  {
    if(imuxconn->conn == conn)
      return imuxconn;
  }
  SMARTLIST_FOREACH_END(imuxconn);

  return NULL;
}

void
channel_imux_handle_state_change_on_orconn(channel_t *chan, or_connection_t *conn,
                                      uint8_t old_state, uint8_t state)
{
  tor_assert(chan);
  tor_assert(conn);
  /* -Werror appeasement */
  tor_assert(old_state == old_state);

  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

  /* Make sure the base connection state makes sense - shouldn't be error,
   * closed or listening. */

  log_info(LD_CHANNEL, "channel %p: connection %p going from state %d -> %d [chan state %d]", imuxchan, conn, old_state, state, chan->state);

  tor_assert(chan->state == CHANNEL_STATE_OPENING ||
             chan->state == CHANNEL_STATE_OPEN ||
             chan->state == CHANNEL_STATE_MAINT ||
             chan->state == CHANNEL_STATE_CLOSING);

  channel_imux_connection_t *imuxconn = channel_imux_find_imux_connection(chan, conn);
  if(!imuxconn) {
    log_info(LD_CHANNEL, "channel %p: could not find connection %p for state change", imuxchan, conn);
    return;
  }

  if(state == OR_CONN_STATE_OPEN) {
    /* if we don't have a bulk conneciton but at least one open connection, set bulk */
    if(get_options()->IMUXSeparateBulkConnection && !imuxchan->bulk_connection) {
      imuxchan->bulk_connection = imuxconn;
      channel_imux_send_command_cell(imuxconn->conn, CELL_BULK_CONN);
      log_info(LD_CHANNEL, "channel %p assigning connection %p as bulk connection", imuxchan, imuxconn);
    } else if(get_options()->IMUXSeparateWebConnection && !imuxchan->web_connection) {
      imuxchan->web_connection = imuxconn;
      channel_imux_send_command_cell(imuxconn->conn, CELL_WEB_CONN);
      log_info(LD_CHANNEL, "channel %p assigning connection %p as web connection", imuxchan, imuxconn);
    }

    int found = 0;
    SMARTLIST_FOREACH_BEGIN(imuxchan->open_connections, channel_imux_connection_t *, c)
    {
      if(c == imuxconn) {
        found = 1;
        break;
      }
    }
    SMARTLIST_FOREACH_END(c);

    if(!found)
      smartlist_add(imuxchan->open_connections, imuxconn);

    /* if this is the first conneciton to open, mark channel open as well */
    if(chan->state != CHANNEL_STATE_OPEN) {
      imuxchan->controlconn = conn;
      channel_change_state(chan, CHANNEL_STATE_OPEN);

      imuxchan->is_canonical = conn->is_canonical;
      imuxchan->link_proto = conn->link_proto;
    }
  }

  /* if we're transitioning from open state, remove from open connection list */
  if(old_state == OR_CONN_STATE_OPEN) {
    channel_imux_connection_t *imuxconn = channel_imux_find_imux_connection(chan, conn);
    if(imuxconn)
      smartlist_remove(imuxchan->open_connections, imuxconn);

    log_info(LD_CHANNEL, "channel %p: (close) has %d open connections [%p]", imuxchan, imuxchan->num_open_connections, conn);
  }


}

static int
channel_imux_compare_cells(const void *_a, const void *_b)
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
channel_imux_flush_circ_queue(channel_imux_circuit_t *circ, or_connection_t *conn)
{
  while(smartlist_len(circ->cell_queue)) {
    channel_imux_cell_t *chan_cell = smartlist_get(circ->cell_queue, 0);

    /* if the cell is out of order, we're missing one so break */
    if(chan_cell->cell.sequence != circ->next_sequence)
      break;

    channel_tls_handle_cell(&(chan_cell->cell), conn);
    circ->next_sequence += 1;
    smartlist_pqueue_pop(circ->cell_queue, channel_imux_compare_cells,
        STRUCT_OFFSET(channel_imux_cell_t, minheap_idx));
  }
}

void
channel_imux_flush_conn_to_next_open(channel_imux_t *imuxchan, or_connection_t *conn)
{
  tor_assert(imuxchan);
  tor_assert(conn);

  if(connection_get_outbuf_len(TO_CONN(conn)) > 0) {
    channel_imux_connection_t *newconn = channel_imux_get_next_open_connection(imuxchan);
    if(!newconn) {
      log_warn(LD_CHANNEL, "channel %p: could not find open connection to move buf to", imuxchan);
    } else {
      log_info(LD_CHANNEL, "channel %p: moving %d bytes from connection %p to %p [%p]", imuxchan,
          TO_CONN(conn)->outbuf_flushlen, conn, newconn->conn, newconn);
      move_buf_to_buf(TO_CONN(newconn->conn)->outbuf, TO_CONN(conn)->outbuf, &(TO_CONN(conn)->outbuf_flushlen));
    }
  }
}


void
channel_imux_handle_cell(cell_t *cell, or_connection_t *conn)
{
  channel_t *chan = conn->chan;
  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

  channel_imux_circuit_t *imuxcirc = channel_imux_find_circuit(imuxchan, cell->circ_id);
  if(!imuxcirc) {
    channel_imux_add_circuit(chan, NULL, cell->circ_id);
    imuxcirc = channel_imux_find_circuit(imuxchan, cell->circ_id);
  }

  log_info(LD_CHANNEL, "channel %p: received cell %d (%d) on circuit %u on conn %p", imuxchan,
          cell->sequence, cell->command, cell->circ_id, conn);

  channel_imux_connection_t *imuxconn = channel_imux_find_connection_by_orconn(imuxchan, conn);
  if(!imuxconn) {
    log_info(LD_CHANNEL, "channel %p: could not find imuxconn for connection %p", imuxchan, conn);
  } else {
     imuxconn->last_active = time(NULL);
  }

  // check if new bulk connection
  if(cell->command == CELL_BULK_CONN) {
    imuxchan->bulk_connection = imuxconn;
    log_info(LD_CHANNEL, "channel %p: received new bulk connection cell on conn %p", imuxchan, imuxconn);
    return;
  }

  // check if new web connection
  if(cell->command == CELL_WEB_CONN) {
    imuxchan->web_connection = imuxconn;
    log_info(LD_CHANNEL, "channel %p: received new web connection cell on conn %p", imuxchan, imuxconn);
    return;
  }

  // check if cell CELL_CLOSING_CONN so we can close this connection */
  if(cell->command == CELL_CLOSING_CONN) {
    log_fn(IMUX_LOG_LEVEL, LD_CHANNEL, "channel %p: received conn close cell on connection %p, closing", imuxchan, imuxconn);
    imuxchan->opening_connections = 0;

    if(imuxconn) {
      if(!imuxconn->marked_for_close) {
        log_info(LD_CHANNEL, "channel %p: conn %p was not marked for close, sending cell to notify other end", imuxchan, imuxconn);
        channel_imux_send_command_cell(conn, CELL_CLOSING_CONN);
      }

      /*channel_imux_flush_conn_to_next_open(imuxchan, conn);*/
      channel_imux_mark_conn_for_close(imuxchan, imuxconn);
      connection_or_close_normally(conn, 1);
    }
    return;
  }

  if(cell->command == CELL_CLOSING_CHAN) {
    log_fn(IMUX_LOG_LEVEL, LD_CHANNEL, "channel %p: received chan closing cell, closing", imuxchan);
    imuxchan->opening_connections = 0;
    channel_mark_for_close(chan);
    return;
  }

  // NETINFO and DESTROY cells don't have sequence numbers, just process them right away
  if(!cell->sequence) {
    channel_tls_handle_cell(cell, conn);
    return;
  }

  /* if cell is next in order, process it and flush queue; otherwise buffer it */
  if(cell->sequence == imuxcirc->next_sequence) {
    channel_tls_handle_cell(cell, conn);
    imuxcirc->next_sequence += 1;

    channel_imux_flush_circ_queue(imuxcirc, conn);
  } else {
    log_info(LD_CHANNEL, "channel %p: received out of order cell %d on circuit %u, was expecting %d", imuxchan,
        cell->sequence, cell->circ_id, imuxcirc->next_sequence);

    if(imuxcirc->next_sequence == 1) {
        log_info(LD_CHANNEL, "channel %p: next sequence is 1, circuit %u ended up on different channel, resetting to %d.", imuxchan, cell->circ_id, cell->sequence + 1);
        channel_tls_handle_cell(cell, conn);
        imuxcirc->next_sequence = cell->sequence + 1;
    } else {
        channel_imux_cell_t *chan_cell = tor_malloc_zero(sizeof(*chan_cell));
        chan_cell->cell.circ_id = cell->circ_id;
        chan_cell->cell.sequence = cell->sequence;
        chan_cell->cell.command = cell->command;
        memcpy(chan_cell->cell.payload, cell->payload, CELL_PAYLOAD_SIZE);

        smartlist_pqueue_add(imuxcirc->cell_queue, channel_imux_compare_cells,
                STRUCT_OFFSET(channel_imux_cell_t, minheap_idx), chan_cell);
    }
  }
}

void
channel_imux_handle_var_cell(var_cell_t *var_cell, or_connection_t *conn)
{
  log_info(LD_CHANNEL, "received var_cell on circuit %u on conn %p", var_cell->circ_id, conn);

  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(conn->chan);

  channel_imux_connection_t *imuxconn = channel_imux_find_connection_by_orconn(imuxchan, conn);
  if(!imuxconn) {
    log_info(LD_CHANNEL, "channel %p: could not find imuxconn for connection %p", imuxchan, conn);
  } else {
     imuxconn->last_active = time(NULL);
  }

  channel_tls_handle_var_cell(var_cell, conn);
}

/* this get's called every second from main through channel.c
 *
 * here we want to determine if we should open or close any more
 * connections based on how much data is being buffered in the
 * connections.  also need to take into account how many total
 * connections are open across all channels to make sure we don't
 * run into the ConnLimit__, disabling us from opening any more connections
 */

int channel_imux_get_chan_max_connections(channel_imux_t *imuxchan)
{
  int total_active_circuits = 0;
  circuit_t *circ;
  /* count all active circuits in the relay */
  TOR_LIST_FOREACH(circ, circuit_get_global_list(), head)
  {
    if(circ->traffic_type == TRAFFIC_TYPE_WEB ||
       (!get_options()->IMUXSeparateBulkConnection && circ->traffic_type == TRAFFIC_TYPE_BULK)) {
      if(circ->n_circ_id != 0)
         total_active_circuits++;

      if(TO_OR_CIRCUIT(circ)->p_circ_id != 0)
        total_active_circuits++;
    }
  }

  /* if there are no active circuits at all, skip housekeeping */
  if(total_active_circuits == 0) {
    return 0;
  }

  int channel_active_circuits = 0;
  SMARTLIST_FOREACH_BEGIN(imuxchan->circuits, channel_imux_circuit_t *, imuxcirc) 
  {
    int traffic_type = IMUXCIRC_TRAFFIC_TYPE(imuxcirc);
    if(imuxcirc->circ_id != 0) {
      if(traffic_type == TRAFFIC_TYPE_WEB || (!get_options()->IMUXSeparateBulkConnection && traffic_type == TRAFFIC_TYPE_BULK)) {
         channel_active_circuits++;
      }
    }
  } 
  SMARTLIST_FOREACH_END(imuxcirc);

  int total_n_conns = get_n_open_sockets();
  int total_max_conns = (get_options()->ConnLimit_ - 32) * get_options()->IMUXConnLimitThreshold;

  int channel_n_conns = smartlist_len(imuxchan->connections);
  int channel_max_conns = (double)channel_active_circuits / (double)total_active_circuits * total_max_conns;
  channel_max_conns = MIN(channel_max_conns, channel_n_conns * 2);
  channel_max_conns = MIN(channel_max_conns, channel_n_conns + (total_max_conns - total_n_conns));
  channel_max_conns = MAX(channel_max_conns, get_options()->IMUXInitConnections);
  if(get_options()->IMUXMaxConnections > 0) {
     channel_max_conns = MIN(channel_max_conns, get_options()->IMUXMaxConnections);
  }

  /*if(channel_n_conns >= channel_max_conns) {*/
      /*channel_max_conns = 1;*/
  /*}*/

  log_fn(IMUX_LOG_LEVEL, LD_CHANNEL, "channel %p: we have %d/%d active circuits, with %d connections (%d open) and %d expected connections [%d sockets, maxconn %d] (opening conns %d)", imuxchan,
      channel_active_circuits, total_active_circuits, channel_n_conns, smartlist_len(imuxchan->open_connections), channel_max_conns,
      total_n_conns, total_max_conns, imuxchan->opening_connections);

  return channel_max_conns;
}

void
channel_imux_housekeeping(channel_t *chan, time_t now)
{
  tor_assert(chan);

  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

  /* skip housekeeping if the channel isn't open */
  if(chan->state != CHANNEL_STATE_OPEN) {
    log_info(LD_CHANNEL, "channel %p is not open (state %d), skipping housekeeping.", chan, chan->state);
    return;
  }

  int channel_n_conns = smartlist_len(imuxchan->connections);
  int channel_max_conns = channel_imux_get_chan_max_connections(imuxchan);

  int i;
  if(imuxchan->opening_connections && channel_n_conns < channel_max_conns) {
    log_fn(IMUX_LOG_LEVEL, LD_CHANNEL, "channel %p: creating %d connections", imuxchan,
            channel_max_conns - channel_n_conns);

    for(i = 0; i < (channel_max_conns - channel_n_conns); i++) {
      channel_imux_connection_t *imuxconn = channel_imux_create_connection(imuxchan);
      if(!imuxconn) {
        log_warn(LD_CHANNEL, "channel %p: error creating connection %d, move to CHANNEL_STATE_ERROR", imuxchan, i + 1);
        chan->reason_for_closing = CHANNEL_CLOSE_FOR_ERROR;
        channel_change_state(chan, CHANNEL_STATE_ERROR);
        return;
      }

      log_fn(IMUX_LOG_LEVEL, LD_CHANNEL, "channel %p: created connection %d with sock %d on channel id " U64_FORMAT ".", imuxchan,
          i + channel_n_conns + 1, TO_CONN(imuxconn->conn)->s, U64_PRINTF_ARG(chan->global_identifier));
    }
  } else if(channel_n_conns > channel_max_conns)  {
    log_fn(IMUX_LOG_LEVEL, LD_CHANNEL, "channel %p: closing %d connections", imuxchan,
            channel_n_conns - channel_max_conns);

    /* go through and find connections to close */
    for(i = 0; i < (channel_n_conns - channel_max_conns); i++) {
      /* first try and find non-open connection to close, otherwise close first open connections */
      channel_imux_connection_t *imuxconn = channel_imux_get_connection_to_close(imuxchan, 0);
      if(!imuxconn && smartlist_len(imuxchan->open_connections) > get_options()->IMUXInitConnections) {
        imuxconn = channel_imux_get_connection_to_close(imuxchan, 1);
      }

      /* if we found a connection, close it */
      if(imuxconn) {
        log_fn(IMUX_LOG_LEVEL, LD_CHANNEL, "channel %p: closing connection %p with socket %d and state %d", imuxchan, imuxconn, TO_CONN(imuxconn->conn)->s,
            TO_CONN(imuxconn->conn)->state);

        channel_imux_close_connection(imuxchan, imuxconn);
      }
    }
  }
}

void 
channel_imux_start_writing(channel_t *chan)
{
  tor_assert(chan);

  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

  SMARTLIST_FOREACH_BEGIN(imuxchan->connections, channel_imux_connection_t *, imuxconn)
  {
    connection_t *conn = TO_CONN(imuxconn->conn);
    if(!connection_is_writing(conn)) {
      /* autotuning, libevent will tell us to add to pending queue */
      connection_start_writing(conn);
    }
  }
  SMARTLIST_FOREACH_END(imuxconn);
}

int
channel_imux_get_num_connections(channel_t *chan)
{
  tor_assert(chan);

  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

  return smartlist_len(imuxchan->connections);
}

void 
channel_imux_notify_conn_error(channel_t *chan, or_connection_t *conn)
{
  tor_assert(chan);
  tor_assert(conn);

  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

  log_warn(LD_CHANNEL, "channel %p: connection %p is closing because of error", imuxchan, conn);

  channel_imux_flush_conn_to_next_open(imuxchan, conn);
}

void
channel_imux_add_connection(channel_t *chan, or_connection_t *conn)
{
	tor_assert(chan);

	channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

	(*(imuxchan->newconn)) = conn;
}

void
channel_imux_remove_connection(channel_t *chan, or_connection_t *conn)
{
  tor_assert(chan);
  tor_assert(conn);

  channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

  channel_imux_connection_t *imuxconn = channel_imux_find_connection_by_orconn(imuxchan, conn);
  
  if(!imuxconn) {
    log_info(LD_CHANNEL, "could not find imuxconn to remove conneciton %p from channel %p", conn, chan);
    return;
  }

  /* if we are closing the bulk connection, pick another one and send the CELL_BULK_CONN cell */
  if(imuxconn == imuxchan->bulk_connection) {
    imuxchan->bulk_connection = channel_imux_get_next_open_connection(imuxchan);
    channel_imux_send_command_cell(imuxchan->bulk_connection->conn, CELL_BULK_CONN);
    
    log_info(LD_CHANNEL, "channel %p: new bulk connection %p", imuxchan, imuxchan->bulk_connection);
  } else  if(imuxconn == imuxchan->web_connection) {
    imuxchan->web_connection = channel_imux_get_next_open_connection(imuxchan);
    channel_imux_send_command_cell(imuxchan->web_connection->conn, CELL_WEB_CONN);
    
    log_info(LD_CHANNEL, "channel %p: new web connection %p", imuxchan, imuxchan->web_connection);
  }

  /* remove connection from lsits */
  smartlist_remove(imuxchan->connections, imuxconn);
  smartlist_remove(imuxchan->open_connections, imuxconn);

  /* reset connection index if we're past upper limmit */
  if(imuxchan->next_conn_index >= smartlist_len(imuxchan->open_connections))  {
    imuxchan->next_conn_index = smartlist_len(imuxchan->open_connections) - 1;
  }

  SMARTLIST_FOREACH_BEGIN(imuxchan->circuits, channel_imux_circuit_t *, imuxcirc) 
  {
    if(imuxcirc->writeconn == imuxconn) {
      imuxcirc->writeconn = NULL;
    }
  }
  SMARTLIST_FOREACH_END(imuxcirc);

  /* check to see if we now have 0 open connections */
  if(smartlist_len(imuxchan->open_connections) == 0 && smartlist_len(imuxchan->connections) > 0) {
      log_warn(LD_CHANNEL, "channel %p: removing connection %p with 0 open connections but %d total connections",
          imuxchan, imuxconn, smartlist_len(imuxchan->connections));
  }

  /* if we have no more connections, close the channel */
  if(smartlist_len(imuxchan->connections) == 0 && TOR_SIMPLEQ_EMPTY(&chan->outgoing_queue)) {
    log_fn(IMUX_LOG_LEVEL, LD_CHANNEL, "channel %p: no more connections open, closing channel", imuxchan);

    /* remove this from the incoming channel map if there */
    channel_imux_conn_entry_t lookup, *ent;
    tor_addr_copy(&lookup.addr, &(imuxchan->addr));
    ent = HT_REMOVE(channel_imux_map, &channel_by_addr, &lookup);
    if(ent) 
      tor_free(ent);

    /* Don't transition if we're already in closing, closed or error */
    if (!(chan->state == CHANNEL_STATE_CLOSING ||
          chan->state == CHANNEL_STATE_CLOSED ||
          chan->state == CHANNEL_STATE_ERROR))  {
      channel_close_from_lower_layer(chan);
    } else {
      channel_closed(chan);
    }
  }
}

channel_imux_circuit_t *
channel_imux_add_circuit(channel_t *chan, circuit_t *circ, circid_t circ_id)
{
	tor_assert(chan);

	channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);
  channel_imux_circuit_t *imuxcirc = channel_imux_find_circuit(imuxchan, circ_id);

	if(imuxcirc) {
		log_info(LD_CHANNEL, "circuit %u already assigned to channel, changing circ from %p to %p", circ_id, imuxcirc->circ, circ);
    imuxcirc->circ = circ;
		return imuxcirc;
	}

	log_info(LD_CHANNEL, "adding circuit %u to channel %p", circ_id, imuxchan);

	imuxcirc = tor_malloc_zero(sizeof(*imuxcirc));
	imuxcirc->circ_id = circ_id;
  imuxcirc->circ = circ;
	imuxcirc->next_sequence = 1;
	imuxcirc->writeconn = NULL;
	imuxcirc->cell_queue = smartlist_new();
	imuxcirc->ewma.ewma_val = 0.0;
	imuxcirc->active = 0;
	smartlist_add(imuxchan->circuits, imuxcirc);

  return imuxcirc;
}

void 
channel_imux_remove_circuit(channel_t *chan, circid_t circid)
{
	tor_assert(chan);

	channel_imux_t *imuxchan = BASE_CHAN_TO_IMUX(chan);

	log_info(LD_CHANNEL, "removing circuit %u from channel %p", circid, imuxchan);

	channel_imux_circuit_t *imuxcirc = channel_imux_find_circuit(imuxchan, circid);
	if(!imuxcirc) {
		log_warn(LD_CHANNEL, "could not find circuit %u on channel %p", circid, imuxchan);
		return;
	}

	if(smartlist_len(imuxcirc->cell_queue) > 0) {
    log_info(LD_CHANNEL, "channel %p: removing circuit %u with %d cells remaining in queue -- flushing now", imuxchan, circid, smartlist_len(imuxcirc->cell_queue));
    channel_imux_connection_t *imuxconn = channel_imux_get_next_open_connection(imuxchan);
    if(!imuxconn)  {
      log_warn(LD_CHANNEL, "channel %p: could not find connection to flush circuit %u on, with %d/%d open connections", imuxchan, circid,
          smartlist_len(imuxchan->open_connections), smartlist_len(imuxchan->connections));
    } else {
      channel_imux_flush_circ_queue(imuxcirc, imuxconn->conn);
    }
	}

	smartlist_free(imuxcirc->cell_queue);
	smartlist_remove(imuxchan->circuits, imuxcirc);
	tor_free(imuxcirc);
}

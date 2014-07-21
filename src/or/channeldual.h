/* * Copyright (c) 2012-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file channeldual.h
 * \brief Header file for channeldual.c
 **/

#ifndef TOR_CHANNELDUAL_H
#define TOR_CHANNELDUAL_H

#include "or.h"
#include "channel.h"

#define BASE_CHAN_TO_DUAL(c) (channel_dual_from_base((c)))
#define DUAL_CHAN_TO_BASE(c) (channel_dual_to_base((c)))

#define DUAL_CHAN_MAGIC 0x8a192427U

#ifdef TOR_CHANNEL_INTERNAL_

struct channel_dual_s {
  /* Base channel_t struct */
  channel_t base_;

  tor_addr_t addr;
  uint16_t port;
  char id_digest[DIGEST_LEN];

  smartlist_t *circuits;

  smartlist_t *connections;
  or_connection_t *lightconn;
  or_connection_t *heavyconn;
  or_connection_t **newconn;

  double light_ewma_total;
  double heavy_ewma_total;
  int light_circuit_count;
  int heavy_circuit_count;
};

#endif /* TOR_CHANNEL_INTERNAL_ */

channel_t * channel_dual_connect(const tor_addr_t *addr, uint16_t port,
                                const char *id_digest);
channel_t * channel_dual_handle_incoming(or_connection_t *orconn);

/* Casts */

channel_t * channel_dual_to_base(channel_dual_t *dualchan);
channel_dual_t * channel_dual_from_base(channel_t *chan);

/* Things for connection_or.c to call back into */
void channel_dual_handle_state_change_on_orconn(channel_t *chan, or_connection_t *conn,
                                      uint8_t old_state, uint8_t state);
void channel_dual_handle_cell(cell_t *cell, or_connection_t *conn);
void channel_dual_handle_var_cell(var_cell_t *var_cell,
                                 or_connection_t *conn);
void channel_dual_add_connection(channel_t *chan, or_connection_t *conn);
void channel_dual_remove_connection(channel_t *chan, or_connection_t *conn);
void channel_dual_add_circuit(channel_t *chan, circuit_t *circ, circid_t circid);

/* Cleanup at shutdown */
void channel_dual_free_all(void);

/* channel_dual_t method declarations */

void channel_dual_close_method(channel_t *chan);
void channel_dual_free_method(channel_t *chan);
const char * channel_dual_describe_transport_method(channel_t *chan);
int channel_dual_get_remote_addr_method(channel_t *chan, tor_addr_t *addr_out);
int channel_dual_get_transport_name_method(channel_t *chan, char **transport_out);
const char *channel_dual_get_remote_descr_method(channel_t *chan, int flags);
int channel_dual_has_queued_writes_method(channel_t *chan);
int channel_dual_is_canonical_method(channel_t *chan, int req);
int
channel_dual_matches_extend_info_method(channel_t *chan,
                                       extend_info_t *extend_info);
int channel_dual_matches_target_method(channel_t *chan,
                                            const tor_addr_t *target);
int channel_dual_write_cell_method(channel_t *chan,
                                         cell_t *cell, circuit_t *circ);
int channel_dual_write_packed_cell_method(channel_t *chan, or_connection_t *conn,
                                                circuit_t *circ, packed_cell_t *packed_cell);
int channel_dual_write_var_cell_method(channel_t *chan,
                                             var_cell_t *var_cell, circuit_t *circ);


#endif


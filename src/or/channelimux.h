/* * Copyright (c) 2012-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file channelimux.h
 * \brief Header file for channelimux.c
 **/

#ifndef TOR_CHANNELIMUX_H
#define TOR_CHANNELIMUX_H

#include "or.h"
#include "channel.h"

#define BASE_CHAN_TO_IMUX(c) (channel_imux_from_base((c)))
#define IMUX_CHAN_TO_BASE(c) (channel_imux_to_base((c)))

#define IMUX_CHAN_MAGIC 0x286ab7f8U

#ifdef TOR_CHANNEL_INTERNAL_

typedef enum channel_imux_schedule_type {
    CHANNEL_IMUX_SCHEDULE_RR_CIRC = 1,
    CHANNEL_IMUX_SCHEDULE_RR_CELL = 2,
    CHANNEL_IMUX_SCHEDULE_BEST_SOCKET = 3,
    CHANNEL_IMUX_SCHEDULE_EWMA = 4,
    CHANNEL_IMUX_SCHEDULE_PCTCP = 5,
    CHANNEL_IMUX_SCHEDULE_SINGLE_WEB = 6,
    CHANNEL_IMUX_SCHEDULE_KIST = 7,
} channel_imux_schedule_type;

typedef struct channel_imux_ewma_t {
    double ewma_val;
    unsigned int last_scale;
} channel_imux_ewma_t;

typedef struct channel_imux_cell_t {
    cell_t cell;
    int minheap_idx;
} channel_imux_cell_t;

typedef struct channel_imux_connection_t {
    or_connection_t *conn;
    channel_imux_ewma_t ewma;
    time_t last_write;
    time_t last_active;
    time_t create_time;
    int in_use;

    int marked_for_close;
} channel_imux_connection_t;

typedef struct channel_imux_circuit_t {
    circuit_t *circ;
    circid_t circ_id;
    int next_sequence;
    smartlist_t *cell_queue;
    int active;

    int cells_written;
    channel_imux_connection_t *writeconn;
    channel_imux_ewma_t ewma;
} channel_imux_circuit_t;

struct channel_imux_s {
  /* Base channel_t struct */
  channel_t base_;
  tor_addr_t addr;
  uint16_t port;
  char id_digest[DIGEST_LEN];

  int is_canonical;
  int link_proto;

  channel_imux_schedule_type schedule_type;

  int num_active_circuits;
  smartlist_t *circuits;
  smartlist_t *connections;
  smartlist_t *open_connections;
  int num_open_connections;
  or_connection_t *controlconn;
  channel_imux_connection_t *bulk_connection;

  int next_conn_index;

  double ewma_scale_factor;
  unsigned int ewma_last_circuit_scale;
  unsigned int ewma_last_connection_scale;

  int opening_connections;

  or_connection_t **newconn;

  time_t last_housekeeping_message;

};

#endif /* TOR_CHANNEL_INTERNAL_ */

channel_t * channel_imux_connect(const tor_addr_t *addr, uint16_t port,
                                const char *id_digest);
channel_t * channel_imux_handle_incoming(or_connection_t *orconn);

/* Casts */

channel_t * channel_imux_to_base(channel_imux_t *imuxchan);
channel_imux_t * channel_imux_from_base(channel_t *chan);

/* Things for connection_or.c to call back into */
void channel_imux_handle_state_change_on_orconn(channel_t *chan, or_connection_t *conn,
                                      uint8_t old_state, uint8_t state);
void channel_imux_handle_cell(cell_t *cell, or_connection_t *conn);
void channel_imux_handle_var_cell(var_cell_t *var_cell,
                                 or_connection_t *conn);
void channel_imux_add_connection(channel_t *chan, or_connection_t *conn);
void channel_imux_remove_connection(channel_t *chan, or_connection_t *conn);
channel_imux_circuit_t *channel_imux_add_circuit(channel_t *chan, circuit_t *circ, circid_t circid);
void channel_imux_remove_circuit(channel_t *chan, circid_t circid);
int channel_imux_get_num_connections(channel_t *chan);

void channel_imux_housekeeping(channel_t *chan, time_t now);
void channel_imux_start_writing(channel_t *chan);

/* Cleanup at shutdown */
void channel_imux_free_all(void);

/* channel_imux_t method declarations */

void channel_imux_close_method(channel_t *chan);
const char * channel_imux_describe_transport_method(channel_t *chan);
int channel_imux_get_remote_addr_method(channel_t *chan, tor_addr_t *addr_out);
const char *channel_imux_get_remote_descr_method(channel_t *chan, int flags);
int channel_imux_get_transport_name_method(channel_t *chan, char **transport_out);
int channel_imux_has_queued_writes_method(channel_t *chan);
int channel_imux_is_canonical_method(channel_t *chan, int req);
int channel_imux_matches_extend_info_method(channel_t *chan,
                                       extend_info_t *extend_info);
int channel_imux_matches_target_method(channel_t *chan,
                                            const tor_addr_t *target);
int channel_imux_write_cell_method(channel_t *chan,
                                         cell_t *cell, circuit_t *circ);
int channel_imux_write_packed_cell_method(channel_t *chan, or_connection_t *conn,
                                                circuit_t *circ, packed_cell_t *packed_cell);
int channel_imux_write_var_cell_method(channel_t *chan,
                                             var_cell_t *var_cell, circuit_t *circ);


#endif


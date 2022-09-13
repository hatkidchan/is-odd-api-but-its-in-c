// x-run: gcc % -lmongoose -o %.elf && ./%.elf
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mongoose.h>
#include <sys/time.h>

#define panic(...) { \
  fprintf(stderr, "!PANIC! at %s:%d\n", __FILE__, __LINE__);\
  fprintf(stderr, __VA_ARGS__); \
  abort(); \
}

typedef struct odd_block {
  uint64_t start;
  uint8_t *block; // 16 MiB or 134217728 numbers
  struct odd_block *next;
} OddBlock;


OddBlock *block_init(uint64_t start);
bool block_in_range(OddBlock blk, uint64_t value);
bool block_check(OddBlock blk, uint64_t value);
void block_add(OddBlock *blk);
bool check_is_odd(uint64_t value);
inline uint64_t get_mem_usage(void);
inline double get_time(void);

OddBlock *blocks_head = NULL;
size_t n_blocks = 0;
uint64_t n_requests = 0;
uint64_t n_allocs_failed = 0;

void api_handler(struct mg_connection *c, int ev, void *evd, void *fnd);

int main(void) {
  struct mg_mgr manager;
  mg_mgr_init(&manager);
  mg_http_listen(&manager, "0.0.0.0:8080", api_handler, NULL);
  for (;;) mg_mgr_poll(&manager, 1000);
  mg_mgr_free(&manager);
  return 0;
}


OddBlock *block_init(uint64_t start) {
  OddBlock *blk = calloc(1, sizeof(OddBlock));
  if (blk == NULL) {
    n_allocs_failed++;
    return NULL;
  }
  if ((blk->block = malloc(0x1000000)) == NULL) {
    free(blk);
    n_allocs_failed++;
    return NULL;
  }
  n_blocks++;
  blk->start = start;
#if 1
  for (uint64_t off = 0; off < 0x8000000; off++) {
    off_t byte_ndx = off >> 3;
    blk->block[byte_ndx] |= ((start + off) % 2) << (off % 8);
  }
#else
  memset(blk->block, 0xaa, 0x1000000);
#endif
  return blk;
}

bool block_in_range(OddBlock blk, uint64_t value) {
  return value >= blk.start && value < (blk.start + 0x8000000);
}

bool block_check(OddBlock blk, uint64_t value) {
  if (!block_in_range(blk, value))
    panic("%zd is outside of the range\n", value);
  off_t offset = value - blk.start;
  return blk.block[offset >> 3] & (1 << (offset % 8)) ? true : false;
}

void block_add(OddBlock *blk) {
  printf("added block %p with start=%zd\n", blk, blk->start);
  if (blocks_head) {
    blk->next = blocks_head;
    blocks_head = blk;
  } else {
    blocks_head = blk;
  }
}

bool check_is_odd(uint64_t value) {
  for (OddBlock *blk = blocks_head; blk != NULL; blk = blk->next) {
    if (block_in_range(*blk, value)) {
      return block_check(*blk, value);
    }
  }

  // no blocks with that number were found
  OddBlock *blk = block_init(value & ~0xFFFFFF);
  if (!blk) return false;
  block_add(blk);
  return block_check(*blk, value);
}

void api_handler(struct mg_connection *c, int ev, void *evd, void *fnd) {
  if (ev == MG_EV_HTTP_MSG) {
    static char url[256];
    struct mg_http_message *hm = evd;
    memset(url, 0, 256);
    memcpy(url, hm->uri.ptr, hm->uri.len);
    if (mg_http_match_uri(hm, "/analytics")) {
      mg_http_reply(c, 200, "Content-Type: application/json\r\n",
          "{"
          "\"ts\":%lf,"
          "\"n_blocks\":%zd,"
          "\"memory\":%zd,"
          "\"last_block_value\":%zd,"
          "\"n_requests\":%zd,"
          "\"n_allocs_failed\":%zd"
          "}",
            get_time(),
            n_blocks,
            get_mem_usage(),
            blocks_head ? blocks_head->start + 0x8000000 - 1 : -1,
            n_requests,
            n_allocs_failed
            );
    } else if (mg_http_match_uri(hm, "/blocks")) {
      mg_printf(c, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
      for (OddBlock *blk = blocks_head; blk; blk = blk->next) {
        mg_http_printf_chunk(c, "block %p (%zd...%zd)\n",
            blk, blk->start, blk->start + 0x8000000 - 1);
      }
      mg_http_printf_chunk(c, "");
    } else if (mg_http_match_uri(hm, "/isEven/*")) {
      uint64_t number;
      sscanf(url, "/isEven/%zd", &number);
      bool res = !check_is_odd(number);
      mg_http_reply(c, 200, "", res ? "true" : "false");
      n_requests++;
    } else if (mg_http_match_uri(hm, "/isOdd/*")) {
      uint64_t number;
      sscanf(url, "/isOdd/%zd", &number);
      bool res = check_is_odd(number);
      mg_http_reply(c, 200, "", res ? "true" : "false");
      n_requests++;
    } else if (mg_http_match_uri(hm, "/lastEven")) {
      mg_http_reply(c, 200, "", "%zd", blocks_head->start + 0x7FFFFFE);
      n_requests++;
    } else if (mg_http_match_uri(hm, "/lastOdd")) {
      mg_http_reply(c, 200, "", "%zd", blocks_head->start + 0x7FFFFFF);
      n_requests++;
    } else {
      mg_http_reply(c, 500, "", "Internal Server Error");
    }
  }
}

uint64_t get_mem_usage(void) {
  FILE *fp = fopen("/proc/self/statm", "r");
  if (!fp) return 0;
  uint64_t res;
  fscanf(fp, "%zd", &res);
  fclose(fp);
  return res * 1024;
}

double get_time(void) {
  struct timeval now;
  gettimeofday(&now, NULL);
  return now.tv_sec + now.tv_usec / 1000000.0;

}

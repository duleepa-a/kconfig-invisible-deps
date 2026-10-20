/*
 * Compiler-generated regression cases for netdep.py's classifier.
 * Build + check with tests/run_classify_cases.sh (inside the Linux container).
 *
 * Each `// EXPECT: <sym> <ACCESS[|ACCESS...]> [field=<path>]` line states that
 * netdep.py must emit at least one xref row for <sym> with one of the listed
 * access kinds. Alternatives (|) cover legitimate compiler variation, e.g.
 * `cmpl $0,g` vs `mov g,%eax; test`.
 */

volatile int g_store;
volatile int g_rmw;
volatile int g_cas;
volatile int g_guard;
volatile int g_bits;
volatile int g_arr[8];
void (*g_handler)(void);
struct st { int enabled; void (*handler)(void); };
struct st g_state;
void cb(void) {}
struct ops { void (*cb)(void); };
struct ops g_ops = { cb };
static volatile int s_cnt;

// EXPECT: g_store STORE
void f_store(void) { g_store = 1; }

// EXPECT: g_rmw RMW
void f_atomic_or(void) { __atomic_fetch_or(&g_rmw, 1, __ATOMIC_SEQ_CST); }

// EXPECT: g_cas RMW
int f_cas(int a) { return __sync_val_compare_and_swap(&g_cas, 0, a); }

// EXPECT: g_handler INDIRECT_CALL_READ
void f_icall(void) { g_handler(); }

// EXPECT: g_handler STORE
// EXPECT: cb ADDR
void f_setptr(void) { g_handler = cb; }

// EXPECT: g_state STORE field=enabled
void f_field_store(void) { g_state.enabled = 1; }

// EXPECT: g_state LOAD|LOAD_GUARD|INDIRECT_CALL_READ field=handler
void f_field_call(void) { g_state.handler(); }

// EXPECT: g_guard LOAD_GUARD|LOAD
int f_guard(void) { return g_guard != 0; }

// EXPECT: g_arr STORE
void f_arr(void) { g_arr[2] = 5; }

// EXPECT: s_cnt RMW|LOAD|STORE
void f_static(void) { s_cnt++; }

// EXPECT: g_bits RMW
void f_bts(void) { __atomic_fetch_or(&g_bits, 1 << 3, __ATOMIC_SEQ_CST); }

// Static initialiser: pointer to cb lives in .data, written by no code.
// EXPECT: cb DATAREF

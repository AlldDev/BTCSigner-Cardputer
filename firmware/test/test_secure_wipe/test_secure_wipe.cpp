// Testa o registro do wipe de emergencia e que os scrubs de stack rodam no
// host. O comportamento real (reset sem dump, stack do loopTask) so pode ser
// verificado no aparelho.
#include <unity.h>

#include "emergency_wipe.h"
#include "secure_wipe.h"

using btcseed::emergency_wipe;
using btcseed::scrub_free_stack;
using btcseed::scrub_stack;
using btcseed::set_emergency_wipe;

namespace {
int g_calls = 0;
void count_call() { g_calls++; }
} // namespace

void setUp(void) {
  g_calls = 0;
  set_emergency_wipe(nullptr);
}
void tearDown(void) { set_emergency_wipe(nullptr); }

static void test_emergency_wipe_without_callback_is_noop(void) {
  emergency_wipe();
  TEST_ASSERT_EQUAL_INT(0, g_calls);
}

static void test_emergency_wipe_calls_callback_every_time(void) {
  set_emergency_wipe(count_call);
  emergency_wipe();
  emergency_wipe();
  TEST_ASSERT_EQUAL_INT(2, g_calls);
}

static void test_emergency_wipe_after_unregister_is_noop(void) {
  set_emergency_wipe(count_call);
  set_emergency_wipe(nullptr);
  emergency_wipe();
  TEST_ASSERT_EQUAL_INT(0, g_calls);
}

static void test_scrubs_run_on_host(void) {
  scrub_stack();
  scrub_free_stack();
  TEST_PASS();
}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_emergency_wipe_without_callback_is_noop);
  RUN_TEST(test_emergency_wipe_calls_callback_every_time);
  RUN_TEST(test_emergency_wipe_after_unregister_is_noop);
  RUN_TEST(test_scrubs_run_on_host);
  return UNITY_END();
}

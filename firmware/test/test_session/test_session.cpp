// Testa a logica de timeout/wipe da sessao com um relogio falso, sem
// depender de hardware ou de esperar o timeout real (3 minutos) passar.
#include <unity.h>

#include "config.h"
#include "session.h"

using btcseed::kSessionTimeoutMs;
using btcseed::MasterKey;
using btcseed::Network;
using btcseed::Session;

namespace {
uint32_t g_fake_millis = 0;
uint32_t fake_millis() { return g_fake_millis; }

MasterKey make_dummy_key() {
  MasterKey mk;
  mk.valid = true;
  mk.master_fingerprint = 0xdeadbeef;
  mk.network = Network::kTestnet;
  mk.account_node.private_key[0] = 0x42; // marcador para checar o wipe
  return mk;
}
} // namespace

void setUp(void) { g_fake_millis = 0; }
void tearDown(void) {}

static void test_starts_inactive(void) {
  Session session(fake_millis);
  TEST_ASSERT_FALSE(session.is_active());
  TEST_ASSERT_FALSE(session.is_expired());
}

static void test_start_activates_and_moves_key(void) {
  Session session(fake_millis);
  MasterKey mk = make_dummy_key();

  session.start(&mk);

  TEST_ASSERT_TRUE(session.is_active());
  TEST_ASSERT_EQUAL_UINT32(0xdeadbeef, session.master_key().master_fingerprint);
  // O chamador perde a copia (foi movida para dentro da sessao).
  TEST_ASSERT_FALSE(mk.valid);
}

static void test_expires_after_timeout(void) {
  Session session(fake_millis);
  MasterKey mk = make_dummy_key();
  session.start(&mk);

  g_fake_millis += kSessionTimeoutMs - 1;
  TEST_ASSERT_FALSE(session.is_expired());

  g_fake_millis += 2; // ultrapassa o limite
  TEST_ASSERT_TRUE(session.is_expired());
}

static void test_touch_resets_timeout(void) {
  Session session(fake_millis);
  MasterKey mk = make_dummy_key();
  session.start(&mk);

  g_fake_millis += kSessionTimeoutMs - 1;
  session.touch();
  g_fake_millis += kSessionTimeoutMs - 1;
  TEST_ASSERT_FALSE(session.is_expired());
}

static void test_end_wipes_secrets(void) {
  Session session(fake_millis);
  MasterKey mk = make_dummy_key();
  session.start(&mk);

  session.end();

  TEST_ASSERT_FALSE(session.is_active());
  TEST_ASSERT_FALSE(session.is_expired());
  TEST_ASSERT_FALSE(session.master_key().valid);
  TEST_ASSERT_EQUAL_UINT32(0, session.master_key().master_fingerprint);
  TEST_ASSERT_EQUAL_UINT8(0, session.master_key().account_node.private_key[0]);
}

static void test_millis_wraparound_does_not_break_timeout(void) {
  Session session(fake_millis);
  MasterKey mk = make_dummy_key();
  g_fake_millis = 0xFFFFFFFFu - 5; // proximo do overflow de uint32_t
  session.start(&mk);

  g_fake_millis += 10; // atravessa o overflow (wrap para um valor pequeno)
  TEST_ASSERT_TRUE(session.is_expired() == (10 >= kSessionTimeoutMs));
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  UNITY_BEGIN();
  RUN_TEST(test_starts_inactive);
  RUN_TEST(test_start_activates_and_moves_key);
  RUN_TEST(test_expires_after_timeout);
  RUN_TEST(test_touch_resets_timeout);
  RUN_TEST(test_end_wipes_secrets);
  RUN_TEST(test_millis_wraparound_does_not_break_timeout);
  return UNITY_END();
}

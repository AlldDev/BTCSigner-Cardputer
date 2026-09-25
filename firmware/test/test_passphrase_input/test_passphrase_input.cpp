#include <unity.h>

#include <cstring>

#include "keys.h"
#include "passphrase_input.h"

using btcseed::PassphraseInput;

void setUp(void) {}
void tearDown(void) {}

static void test_starts_empty_and_masked(void) {
  PassphraseInput p;
  TEST_ASSERT_TRUE(p.is_empty());
  TEST_ASSERT_FALSE(p.is_visible());

  char out[16];
  p.render_display(out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("", out);
}

static void test_add_char_and_masking(void) {
  PassphraseInput p;
  TEST_ASSERT_TRUE(p.add_char('h'));
  TEST_ASSERT_TRUE(p.add_char('i'));
  TEST_ASSERT_TRUE(p.add_char('!'));
  TEST_ASSERT_EQUAL_INT(3, p.length());
  TEST_ASSERT_EQUAL_STRING("hi!", p.value());

  char out[16];
  p.render_display(out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("***", out); // mascarado por padrao

  p.toggle_visibility();
  TEST_ASSERT_TRUE(p.is_visible());
  p.render_display(out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("hi!", out);
}

static void test_rejects_non_printable(void) {
  PassphraseInput p;
  TEST_ASSERT_FALSE(p.add_char('\n'));
  TEST_ASSERT_FALSE(p.add_char('\t'));
  TEST_ASSERT_FALSE(p.add_char(static_cast<char>(0x01)));
  TEST_ASSERT_FALSE(p.add_char(static_cast<char>(0x7f)));
  TEST_ASSERT_TRUE(p.is_empty());
}

static void test_backspace(void) {
  PassphraseInput p;
  TEST_ASSERT_FALSE(p.backspace()); // vazio: no-op
  p.add_char('a');
  p.add_char('b');
  TEST_ASSERT_TRUE(p.backspace());
  TEST_ASSERT_EQUAL_STRING("a", p.value());
  TEST_ASSERT_TRUE(p.backspace());
  TEST_ASSERT_TRUE(p.is_empty());
}

static void test_respects_max_length(void) {
  PassphraseInput p;
  for (int i = 0; i < 256; i++) {
    TEST_ASSERT_TRUE(p.add_char('a'));
  }
  TEST_ASSERT_EQUAL_INT(256, p.length());
  TEST_ASSERT_FALSE(p.add_char('a')); // estourou o limite
}

static void test_wipe_clears_buffer(void) {
  PassphraseInput p;
  p.add_char('s');
  p.add_char('e');
  p.add_char('c');
  p.toggle_visibility();
  p.wipe();

  TEST_ASSERT_TRUE(p.is_empty());
  TEST_ASSERT_FALSE(p.is_visible());
  TEST_ASSERT_EQUAL_STRING("", p.value());
}

static void test_format_fingerprint(void) {
  char out[9];
  btcseed::format_fingerprint(0xDEADBEEF, out);
  TEST_ASSERT_EQUAL_STRING("deadbeef", out);
  btcseed::format_fingerprint(0x00000000, out);
  TEST_ASSERT_EQUAL_STRING("00000000", out);
  btcseed::format_fingerprint(0x0000000f, out);
  TEST_ASSERT_EQUAL_STRING("0000000f", out);
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  UNITY_BEGIN();
  RUN_TEST(test_starts_empty_and_masked);
  RUN_TEST(test_add_char_and_masking);
  RUN_TEST(test_rejects_non_printable);
  RUN_TEST(test_backspace);
  RUN_TEST(test_respects_max_length);
  RUN_TEST(test_wipe_clears_buffer);
  RUN_TEST(test_format_fingerprint);
  return UNITY_END();
}

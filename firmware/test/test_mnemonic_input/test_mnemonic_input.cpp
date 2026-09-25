#include <unity.h>

#include <cstring>
#include <initializer_list>

#include "mnemonic_input.h"

using btcseed::MnemonicInput;

namespace {
// Digita uma palavra inteira, letra por letra, e confirma. Assume que a
// palavra existe na wordlist BIP39 (senao TEST_ASSERT falha no meio).
void type_word(MnemonicInput &input, const char *word) {
  for (const char *p = word; *p != '\0'; p++) {
    TEST_ASSERT_TRUE_MESSAGE(input.try_add_letter(*p), word);
  }
  TEST_ASSERT_TRUE_MESSAGE(input.confirm_word(), word);
}
} // namespace

void setUp(void) {}
void tearDown(void) {}

static void test_rejects_letter_with_no_matching_word(void) {
  MnemonicInput input(12);
  TEST_ASSERT_TRUE(input.try_add_letter('z'));  // "z" -> zebra, zero, zone, zoo...
  TEST_ASSERT_FALSE(input.try_add_letter('z')); // "zz" -> nenhuma palavra
  TEST_ASSERT_EQUAL_STRING("z", input.current_prefix());
}

static void test_unique_candidate_autodetected(void) {
  MnemonicInput input(12);
  for (char c : {'a', 'b', 'a', 'n', 'd'}) {
    TEST_ASSERT_TRUE(input.try_add_letter(c));
  }
  TEST_ASSERT_TRUE(input.has_unique_candidate());
  TEST_ASSERT_EQUAL_STRING("abandon", input.unique_candidate());

  TEST_ASSERT_TRUE(input.confirm_word());
  TEST_ASSERT_EQUAL_INT(1, input.current_word_index());
}

static void test_multiple_candidates_navigation(void) {
  MnemonicInput input(12);
  TEST_ASSERT_TRUE(input.try_add_letter('a'));
  TEST_ASSERT_TRUE(input.try_add_letter('b'));
  int count = input.count_candidates();
  TEST_ASSERT_GREATER_THAN_INT(1, count); // about, above, absent, absorb...
  TEST_ASSERT_FALSE(input.has_unique_candidate());

  const char *first = input.nth_candidate(input.selected_candidate_index());
  input.next_candidate();
  const char *second = input.nth_candidate(input.selected_candidate_index());
  TEST_ASSERT_NOT_EQUAL(0, strcmp(first, second));

  input.prev_candidate();
  TEST_ASSERT_EQUAL_STRING(first,
                           input.nth_candidate(input.selected_candidate_index()));
}

static void test_backspace_returns_to_previous_word(void) {
  MnemonicInput input(12);
  type_word(input, "abandon");
  TEST_ASSERT_EQUAL_INT(1, input.current_word_index());

  TEST_ASSERT_TRUE(input.backspace()); // prefixo vazio -> volta pra palavra 0
  TEST_ASSERT_EQUAL_INT(0, input.current_word_index());
}

static void test_backspace_noop_on_first_word_empty_prefix(void) {
  MnemonicInput input(12);
  TEST_ASSERT_FALSE(input.backspace());
  TEST_ASSERT_EQUAL_INT(0, input.current_word_index());
}

static void test_full_valid_mnemonic_matches_official_vector(void) {
  MnemonicInput input(12);
  const char *words[] = {"abandon", "abandon", "abandon", "abandon",
                         "abandon", "abandon", "abandon", "abandon",
                         "abandon", "abandon", "abandon", "about"};
  for (const char *w : words) {
    type_word(input, w);
  }
  TEST_ASSERT_TRUE(input.is_complete());

  char mnemonic[256];
  TEST_ASSERT_TRUE(input.build_mnemonic(mnemonic, sizeof(mnemonic)));
  TEST_ASSERT_EQUAL_STRING(
      "abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon about",
      mnemonic);
  TEST_ASSERT_TRUE(input.validate_checksum());
}

static void test_invalid_checksum_can_be_fixed_via_restart_word(void) {
  MnemonicInput input(12);
  // Ultima palavra errada de proposito: checksum invalido.
  const char *words[] = {"abandon", "abandon", "abandon", "abandon",
                         "abandon", "abandon", "abandon", "abandon",
                         "abandon", "abandon", "abandon", "abandon"};
  for (const char *w : words) {
    type_word(input, w);
  }
  TEST_ASSERT_TRUE(input.is_complete());
  TEST_ASSERT_FALSE(input.validate_checksum());

  // Corrige so a ultima palavra (indice 11), sem reexibir as demais.
  input.restart_word(11);
  TEST_ASSERT_EQUAL_INT(11, input.current_word_index());
  type_word(input, "about");

  TEST_ASSERT_TRUE(input.is_complete());
  TEST_ASSERT_TRUE(input.validate_checksum());
}

static void test_wipe_resets_state(void) {
  MnemonicInput input(12);
  type_word(input, "abandon");
  input.wipe();

  TEST_ASSERT_EQUAL_INT(0, input.current_word_index());
  TEST_ASSERT_EQUAL_STRING("", input.current_prefix());
  TEST_ASSERT_FALSE(input.is_complete());
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  UNITY_BEGIN();
  RUN_TEST(test_rejects_letter_with_no_matching_word);
  RUN_TEST(test_unique_candidate_autodetected);
  RUN_TEST(test_multiple_candidates_navigation);
  RUN_TEST(test_backspace_returns_to_previous_word);
  RUN_TEST(test_backspace_noop_on_first_word_empty_prefix);
  RUN_TEST(test_full_valid_mnemonic_matches_official_vector);
  RUN_TEST(test_invalid_checksum_can_be_fixed_via_restart_word);
  RUN_TEST(test_wipe_resets_state);
  return UNITY_END();
}

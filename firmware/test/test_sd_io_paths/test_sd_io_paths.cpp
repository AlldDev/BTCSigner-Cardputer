// Testa a logica pura de nomes/caminhos de sd_io_paths.cpp — sem tocar em
// hardware nenhum. Cobre os casos maliciosos citados na secao 14 do spec
// (nomes de arquivo com path traversal, etc.).
#include <unity.h>

#include <cstring>

#include "config.h"
#include "sd_io.h"

using namespace btcseed;

void setUp(void) {}
void tearDown(void) {}

static void test_sanitize_accepts_normal_names(void) {
  char out[kMaxFilenameLen + 1];
  TEST_ASSERT_TRUE(sanitize_filename("pagamento.psbt", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("pagamento.psbt", out);

  TEST_ASSERT_TRUE(sanitize_filename("saque-01 final.psbt", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("saque-01 final.psbt", out);
}

static void test_sanitize_rejects_empty_and_too_long(void) {
  char out[kMaxFilenameLen + 1];
  TEST_ASSERT_FALSE(sanitize_filename("", out, sizeof(out)));

  char too_long[kMaxFilenameLen + 10];
  memset(too_long, 'a', sizeof(too_long) - 1);
  too_long[sizeof(too_long) - 1] = '\0';
  TEST_ASSERT_FALSE(sanitize_filename(too_long, out, sizeof(out)));
}

static void test_sanitize_rejects_path_traversal(void) {
  char out[kMaxFilenameLen + 1];
  TEST_ASSERT_FALSE(sanitize_filename("..", out, sizeof(out)));
  TEST_ASSERT_FALSE(sanitize_filename("../etc/passwd", out, sizeof(out)));
  TEST_ASSERT_FALSE(sanitize_filename("a/../../b.psbt", out, sizeof(out)));
  TEST_ASSERT_FALSE(sanitize_filename("foo..psbt", out, sizeof(out)));
}

static void test_sanitize_rejects_slashes_and_control_chars(void) {
  char out[kMaxFilenameLen + 1];
  TEST_ASSERT_FALSE(sanitize_filename("/etc/passwd", out, sizeof(out)));
  TEST_ASSERT_FALSE(sanitize_filename("sub/dir.psbt", out, sizeof(out)));
  TEST_ASSERT_FALSE(sanitize_filename("back\\slash.psbt", out, sizeof(out)));

  char with_control[] = {'a', 'b', 'c', 0x01, '.', 'p', 's', 'b', 't', '\0'};
  TEST_ASSERT_FALSE(sanitize_filename(with_control, out, sizeof(out)));
}

static void test_sanitize_respects_output_capacity(void) {
  char tiny[4];
  TEST_ASSERT_FALSE(sanitize_filename("pagamento.psbt", tiny, sizeof(tiny)));
}

static void test_has_extension_case_insensitive(void) {
  TEST_ASSERT_TRUE(has_extension("a.psbt", ".psbt"));
  TEST_ASSERT_TRUE(has_extension("A.PSBT", ".psbt"));
  TEST_ASSERT_TRUE(has_extension("weird.PsBt", ".psbt"));
  TEST_ASSERT_FALSE(has_extension("a.psbt.txt", ".psbt"));
  TEST_ASSERT_FALSE(has_extension("psbt", ".psbt"));
  TEST_ASSERT_FALSE(has_extension("a.pdf", ".psbt"));
}

static void test_join_path_handles_trailing_slash(void) {
  char out[64];
  TEST_ASSERT_TRUE(join_path("/psbt", "a.psbt", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("/psbt/a.psbt", out);

  TEST_ASSERT_TRUE(join_path("/psbt/", "a.psbt", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("/psbt/a.psbt", out);

  TEST_ASSERT_TRUE(join_path("/", "a.psbt", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("/a.psbt", out);
}

static void test_join_path_respects_output_capacity(void) {
  char tiny[5];
  TEST_ASSERT_FALSE(join_path("/psbt", "a.psbt", tiny, sizeof(tiny)));
}

static void test_build_signed_filename_inserts_before_extension(void) {
  char out[kMaxFilenameLen + 1];
  TEST_ASSERT_TRUE(build_signed_filename("pagamento.psbt", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("pagamento_signed.psbt", out);
}

static void test_build_signed_filename_without_extension_appends_suffix(void) {
  char out[kMaxFilenameLen + 1];
  TEST_ASSERT_TRUE(build_signed_filename("pagamento", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("pagamento_signed", out);
}

static void test_build_signed_filename_respects_output_capacity(void) {
  char tiny[8];
  TEST_ASSERT_FALSE(build_signed_filename("pagamento.psbt", tiny, sizeof(tiny)));
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  UNITY_BEGIN();
  RUN_TEST(test_sanitize_accepts_normal_names);
  RUN_TEST(test_sanitize_rejects_empty_and_too_long);
  RUN_TEST(test_sanitize_rejects_path_traversal);
  RUN_TEST(test_sanitize_rejects_slashes_and_control_chars);
  RUN_TEST(test_sanitize_respects_output_capacity);
  RUN_TEST(test_has_extension_case_insensitive);
  RUN_TEST(test_join_path_handles_trailing_slash);
  RUN_TEST(test_join_path_respects_output_capacity);
  RUN_TEST(test_build_signed_filename_inserts_before_extension);
  RUN_TEST(test_build_signed_filename_without_extension_appends_suffix);
  RUN_TEST(test_build_signed_filename_respects_output_capacity);
  return UNITY_END();
}

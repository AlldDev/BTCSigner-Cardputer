// Unico canal de dados do firmware (secao 3/9/10/11 do spec): listagem,
// leitura e escrita no microSD. Nenhum segredo (seed, passphrase, chave
// privada, xprv, entropia) e escrito por nenhuma funcao deste arquivo — os
// chamadores (psbt.cpp, main.cpp) so passam para ca dados publicos (PSBTs
// assinadas, xpub/enderecos).
//
// Este arquivo e dividido em duas partes:
//   - Logica pura de nomes/caminhos (sanitize_filename, join_path, etc.),
//     implementada em sd_io_paths.cpp — SEM nenhum include do Arduino/SD,
//     por isso roda e e testada tambem no host (`pio test -e native`).
//   - E/S de fato no cartao, implementada em sd_io.cpp usando SD.h/SPI.h —
//     so compila no ambiente `cardputer` (precisa do hardware).
#pragma once

#include <cstddef>
#include <cstdint>

#include "config.h"

namespace btcseed {

// --- logica pura de nomes/caminhos (sd_io_paths.cpp) ------------------------

// Aceita so letras, digitos e os separadores '-', '_', '.', ' '; rejeita
// nomes vazios, mais longos que kMaxFilenameLen, contendo ".." (path
// traversal) ou qualquer caractere fora desse conjunto (inclui barras e
// caracteres de controle). Copia o nome (com terminador nulo) para `out`
// se aceito.
bool sanitize_filename(const char *name, char *out, size_t out_cap);

// True se `name` termina com `ext`, comparando sem diferenciar maiusculas
// de minusculas.
bool has_extension(const char *name, const char *ext);

// Junta dir + "/" + name em `out` (dir pode ou nao terminar com '/').
bool join_path(const char *dir, const char *name, char *out, size_t out_cap);

// Nome de saida a partir do nome de entrada, inserindo kSignedSuffix antes
// da extensao kPsbtExtension (ex: "pagamento.psbt" ->
// "pagamento_signed.psbt"). Se `name` nao terminar em kPsbtExtension, o
// sufixo e so anexado ao final do nome original.
bool build_signed_filename(const char *name, char *out, size_t out_cap);

// --- E/S no cartao (sd_io.cpp, requer hardware) -----------------------------

struct PsbtFileEntry {
  char name[kMaxFilenameLen + 1] = {0}; // so o nome do arquivo, sem diretorio
};

// Inicializa SPI + monta o cartao. Chamar uma vez antes de qualquer outra
// funcao de E/S abaixo. Retorna false se nao houver cartao ou a montagem
// falhar (nesse caso nenhuma operacao de PSBT deve prosseguir).
bool sd_init();

// Lista arquivos terminados em kPsbtExtension dentro de kPsbtDir; se esse
// diretorio nao existir no cartao, cai para a raiz. Nomes que nao passem
// em sanitize_filename() sao silenciosamente ignorados (nao aparecem no
// menu — mais seguro do que arriscar exibir/usar um nome estranho).
// Retorna a quantidade encontrada (0 a max_files).
int list_psbt_files(PsbtFileEntry *out, int max_files);

// Le o arquivo `filename` (como retornado por list_psbt_files, sem
// diretorio) inteiro para `buf`. Retorna false se nao existir, se falhar a
// leitura, ou se o tamanho exceder kMaxPsbtFileSize ou buf_cap.
bool read_psbt_file(const char *filename, uint8_t *buf, size_t buf_cap,
                    size_t *out_len);

// Grava `data` (a PSBT assinada) com o nome build_signed_filename(
// original_filename), no mesmo diretorio de onde os .psbt sao listados. A
// escrita e atomica: primeiro vai para um arquivo temporario, que so e
// renomeado para o nome final se a escrita completar por inteiro. Se o
// cartao for removido no meio do processo (ou qualquer outra falha
// ocorrer), o temporario e removido e a funcao retorna false — nunca fica
// um arquivo parcial com o nome final (secao 11 do spec).
bool write_signed_psbt(const char *original_filename, const uint8_t *data,
                      size_t len);

// Grava um arquivo de texto simples na raiz do cartao (ex: wallet_export.txt
// da secao 10 do spec). Mesma garantia de escrita atomica acima.
bool write_text_file(const char *path, const char *text);

} // namespace btcseed

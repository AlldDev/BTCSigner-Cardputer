// Limpeza de pilha. Funcoes vendorizadas (trezor-crypto: SHA-2/HMAC/PBKDF2,
// AES, RFC6979) deixam estado secreto na stack sem zerar, e nao podemos
// edita-las. Sobrescrevemos a regiao abaixo do frame de quem chama.
#pragma once

namespace btcseed {

// Sobrescreve 1,5 KB de stack abaixo do frame atual. Usado logo depois de
// uma operacao pontual (backup RFID).
void scrub_stack();

// Sobrescreve toda a stack livre da task atual (no aparelho), mantendo o
// canario e a watchpoint de fim de stack do FreeRTOS intactos. Chamado no fim
// de cada loop(), cobre qualquer caminho executado abaixo dele. No host cai
// no scrub_stack().
void scrub_free_stack();

} // namespace btcseed

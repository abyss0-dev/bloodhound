#include <stdint.h>

__attribute__((naked, noinline, used))
static void task_finished(
    uint64_t task_id __attribute__((unused)),
    uint32_t result __attribute__((unused))
) {
    __asm__ volatile(
        ".Labyss0_peer_probe:\n\t"
        "nop\n\t"
        "ret\n\t"
        ".pushsection .note.stapsdt,\"\",@note\n\t"
        ".balign 4\n\t"
        ".long 8, .Labyss0_peer_desc_end-.Labyss0_peer_desc, 3\n\t"
        ".asciz \"stapsdt\"\n\t"
        ".balign 4\n\t"
        ".Labyss0_peer_desc:\n\t"
        ".quad .Labyss0_peer_probe\n\t"
        ".quad 0\n\t"
        ".quad 0\n\t"
        ".asciz \"abyss0_peer\"\n\t"
        ".asciz \"task_finished\"\n\t"
        ".asciz \"8@%rdi 8@%rsi\"\n\t"
        ".balign 4\n\t"
        ".Labyss0_peer_desc_end:\n\t"
        ".popsection\n\t"
    );
}

int main(void) {
    task_finished(99, 0);
    return 0;
}

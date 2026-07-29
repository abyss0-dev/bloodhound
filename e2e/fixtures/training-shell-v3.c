#include <stdint.h>
#include <stdio.h>

#ifndef USDT_OPERANDS
#define USDT_OPERANDS "8@%rdi 8@%rsi 8@%rdx 8@%rcx 8@%r8 8@%r9"
#endif

#ifndef USDT_SEMAPHORE
#define USDT_SEMAPHORE 0
#endif

// A real writable semaphore symbol for the static-USDT fixture. The Linux
// uprobe PMU increments it while a semaphore-backed link is active.
volatile unsigned short usdt_semaphore __attribute__((used));

#define STRINGIFY_INNER(value) #value
#define STRINGIFY(value) STRINGIFY_INNER(value)

/*
 * This uses a naked function so the six declared USDT operands remain the
 * SysV x86_64 argument registers at the static probe location. The matching
 * .note.stapsdt record is deliberately emitted here rather than discovered
 * from a function symbol by Bloodhound.
 */
__attribute__((naked, noinline, used))
static void simple_command_completed(
    uint32_t shell_pid __attribute__((unused)),
    uint64_t command_id __attribute__((unused)),
    uint32_t command_kind __attribute__((unused)),
    const char *command_name __attribute__((unused)),
    uint32_t semantic_flags __attribute__((unused)),
    int32_t exit_status __attribute__((unused))
) {
    __asm__ volatile(
        ".Labyss0_shell_probe:\n\t"
        "nop\n\t"
        "ret\n\t"
        ".pushsection .note.stapsdt,\"\",@note\n\t"
        ".balign 4\n\t"
        ".long 8, .Labyss0_shell_desc_end-.Labyss0_shell_desc, 3\n\t"
        ".asciz \"stapsdt\"\n\t"
        ".balign 4\n\t"
        ".Labyss0_shell_desc:\n\t"
        ".quad .Labyss0_shell_probe\n\t"
        ".quad 0\n\t"
        ".quad " STRINGIFY(USDT_SEMAPHORE) "\n\t"
        ".asciz \"abyss0_shell\"\n\t"
        ".asciz \"simple_command_completed\"\n\t"
        ".asciz \"" USDT_OPERANDS "\"\n\t"
        ".balign 4\n\t"
        ".Labyss0_shell_desc_end:\n\t"
        ".popsection\n\t"
    );
}

#ifdef MULTI_LOCATION
__attribute__((naked, noinline, used))
static void simple_command_completed_second(
    uint32_t shell_pid __attribute__((unused)),
    uint64_t command_id __attribute__((unused)),
    uint32_t command_kind __attribute__((unused)),
    const char *command_name __attribute__((unused)),
    uint32_t semantic_flags __attribute__((unused)),
    int32_t exit_status __attribute__((unused))
) {
    __asm__ volatile(
        ".Labyss0_shell_probe_second:\n\t"
        "nop\n\t"
        "ret\n\t"
        ".pushsection .note.stapsdt,\"\",@note\n\t"
        ".balign 4\n\t"
        ".long 8, .Labyss0_shell_desc_second_end-.Labyss0_shell_desc_second, 3\n\t"
        ".asciz \"stapsdt\"\n\t"
        ".balign 4\n\t"
        ".Labyss0_shell_desc_second:\n\t"
        ".quad .Labyss0_shell_probe_second\n\t"
        ".quad 0\n\t"
        ".quad " STRINGIFY(USDT_SEMAPHORE) "\n\t"
        ".asciz \"abyss0_shell\"\n\t"
        ".asciz \"simple_command_completed\"\n\t"
        ".asciz \"" USDT_OPERANDS "\"\n\t"
        ".balign 4\n\t"
        ".Labyss0_shell_desc_second_end:\n\t"
        ".popsection\n\t"
    );
}
#endif

int main(void) {
    const char *command_name = "echo";
#ifdef UNREADABLE_COMMAND_NAME
    command_name = (const char *)0x1;
#endif
    simple_command_completed(412, 17, 0, command_name, 1, 0);
#ifdef MULTI_LOCATION
    simple_command_completed_second(412, 18, 0, command_name, 1, 0);
#endif
    return 0;
}

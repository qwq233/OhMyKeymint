#[cfg(target_arch = "x86_64")]
#[test]
fn x86_64_stack_padding_preserves_abi_entry_alignment() {
    const START_SP_MOD_16: usize = 0;
    for stack_arg_count in 0..8 {
        let padding = if stack_arg_count % 2 == 1 { std::mem::size_of::<usize>() } else { 0 };
        let pushed_bytes = (stack_arg_count + 1) * std::mem::size_of::<usize>();
        let final_mod = (START_SP_MOD_16 + 16 - (padding + pushed_bytes) % 16) % 16;
        assert_eq!(final_mod, 8, "stack_arg_count={stack_arg_count} padding={padding}");
    }
}

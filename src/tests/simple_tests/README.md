## Preprocessing directives

In tests in `.asm` files it is possible to use several additional directives (not stable):
- `print("<TEXT>")` - print text `<TEXT>` in console. Max length of text is 30 symbols
- `print(<src>)` - print value of `<src>` (register/constant/etc) in console
- `print("<TEXT>", <src>)` - print text `<TEXT>` and value of `<src>` in console. Max length of text is 30 symbols
- `printPtr(<ptr>)` - print value of `<ptr>` (fat pointer) in console
- `printPtr("<TEXT>", <ptr>)` - print text `<TEXT>` and value of `<ptr>` (fat pointer) in console. Max length of text is 30 symbols
- `revert("<TEXT>")` - panic with message `<TEXT>`. Max length of text is 30 symbols
- `<ADDRESS.asm>` - will be replaced with the hash of `ADDRESS.asm` additional contract
- `set_storage_cold()` - sets the storage slot refund to be cold
- `set_storage_warm(<u32>)` - sets the storage slot refund to be warm with a value of `<u32>`

## Templating

`compile_asm_template` can be used to replace entries like `${<KEY>}` with values from `Dictionary` (`HashMap<&str, &str>`). For example:

```asm
    add ${src0} r0 r1
``` 

will be replaced by `dictionary.get("src0")`. 

This can be used to simplify creation of new tests. For example, you can create a template like this:

```asm
    .text
    .globl	__entry
__entry:
.main:
        ${opcode} ${src0}, ${src1}, ${dst0}
        ret.ok r0
```

and then generate and test different sets of parameters. Also can be used for "fuzzy-style" tests.
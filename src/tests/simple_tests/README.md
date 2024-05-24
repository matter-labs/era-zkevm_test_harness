## Preprocessing directives

In tests in `.asm` files it is possible to use several additional directives (not stable):
- `print("<TEXT>")` - print text `<TEXT>` in console. Max length of text is 30 symbols
- `print(<src>)` - print value of `<src>` (register/constant/etc) in console
- `print("<TEXT>", <src>)` - print text `<TEXT>` and value of `<src>` in console. Max length of text is 30 symbols
- `printPtr(<ptr>)` - print value of `<ptr>` (fat pointer) in console
- `printPtr("<TEXT>", <ptr>)` - print text `<TEXT>` and value of `<ptr>` (fat pointer) in console. Max length of text is 30 symbols
- `revert("<TEXT>")` - panic with message `<TEXT>`. Max length of text is 30 symbols
- `<ADDRESS.asm>` - will be replaced with the hash of `ADDRESS.asm` additional contract

## Templating

`compile_asm_template` can be used to replace entries like `${<KEY>}` with values from `Dictionary` (`HashMap<&str, &str>`). For example:

```asm
    add ${src0} r0 r1
``` 

will be replaced by `dictionary.get("src0")`
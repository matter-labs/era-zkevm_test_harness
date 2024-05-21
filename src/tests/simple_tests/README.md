In tests in `.asm` files it is possible to use several additional directives (not stable):
- `print("<TEXT>")` - print text `<TEXT>` in console. Max length of text is 30 symbols
- `print(<src>)` - print value of `<src>` (register/constant/etc) in console
- `printPtr(<ptr>)` - print value of `<ptr>` (fat pointer) in console
- `revert("<TEXT>")` - panic with message `<TEXT>`. Max length of text is 30 symbols
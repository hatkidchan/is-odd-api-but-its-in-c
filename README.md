# Is Odd API

*This ๐ is ๐ฑ๐ฐ a ๐ simple API that ๐ returns ๐ whether ๐๐ a ๐ฅ number ๐ฆ๐ข is ๐๐ฆ odd ๐คฅ or ๐ฐ not. โ With ๐๐ผ this ๐ฝ๐ API you ๐ญ๐ can ๐๐ซ check โ if โ a number โค is ๐ฆ odd ๐คฅ or not. ๐*\
*However, ๐ฏ there's a ๐ฐ๐พ twist ๐๐...*

Implementation in Java (v1.0): [by rferee](https://github.com/rferee/is-odd-api)

## Features ๐

- Even more ๐ณ blazing ๐ฅ๐ฅ fast ๐๐!
- Even more ๐ฅ scalable ๐๐!
- Even more ๐จ native ๐บ๐ธ๐บ๐ธ support ๐บ๐ธ๐บ๐ธ for ๐บ๐ธ๐บ๐ธ all ๐บ๐ธ๐บ๐ธ operating ๐บ๐ธ๐บ๐ธ systems ๐บ๐ธ๐บ๐ธ!
- More than ๐ซฃ 100% ๐๐ uptime ๐๐!
- More than ๐ซ  100% ๐ฏ vegan ๐ฑ๐ฑ๐ฑ!

*...and ๐ much ๐๐ฆ more!*

###### *This description was generated by GitHub Copilot ๐ค*

## Requirements ๐

### Example ๐ค System โโ Configuration ๐ฅ

We are performing tests right now. 

## Screenshots ๐ท

Current usage for ๐ `is-odd-api-dev` is: ๐ก
To be added

## API Methods ๐ก

### `/isEven/{number}`

Can be ๐ฑ๐ used to ๐ฆ๐ determine ๐ค whether or ๐ฑ not ๐ซโ the ๐๐ฝ number is ๐ even. ๐๐

**Returns:** [`ResponseNotFound`](#responsenotfound) ๐ณ or [`ResponseIsEven`](#responseiseven) ๐

### `/isOdd/{number}`

Can ๐ซ๐ฆ be used ๐๐ to determine ๐ง whether or ๐ฎ๐ฆ not โ the ๐ number ๐ฆ๐ง is odd. ๐คฅ๐

**Returns:** [`ResponseNotFound`](#responsenotfound) or [`ResponseIsOdd`](#responseisodd)

### `/lastEven`

**Returns:** last โณ indexed ๐ even ๐ญ number ๐ฆ๐ข

### `/lastOdd`

**Returns:** last โณ indexed ๐ odd ๐คจ number ๐ฆ๐ข

## API Objects ๐ฆ

### `ResponseIsOdd`

Property `odd` ๐ will ๐ be `true` if `{number}` ๐ฆ๐ฆ is ๐ณ odd ๐ and ๐ฃ๐ `false` if ๐ `{number}` is ๐ even.

```json
{
  "odd": true
}
```

### `ResponseIsEven`

Property `even` ๐๐ will be `true` โญโ if ๐ซ๐คฅ `{number}` ๐ข is even and ๐๐ `false` ๐ณโ if ๐ `{number}` is ๐ณ odd.

```json
{
  "even": true
}
```

### `ResponseNotFound`

Returns when ๐ค๐ the ๐ฉ number wasn't indexed yet. ๐โ

```json
{
  "message": "This number is not indexed yet."
}
```

## Liability ๐ and ๐ Disclaimer ๐

This ๐ฉ๐ฌ is ๐ a ๐๐คก joke project. โฌ We ๐ง decided to ๐ฆ rent out ๐ฏ the ๐๐ผ machine ๐ฆ with ๐ฒ๐ more โ๐ than โฌ๐ฝ a 1 TB of ๐ฒ RAM ๐ and 96 cores of ๐ฒ CPU ๐ฅ to ๐ index ๐๐ all ๐๐ฆ numbers ๐๐ from 1 โ๐ต to ๐ `long` โ๐ต maximum. ๐๐

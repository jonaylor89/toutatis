# Toutatis

Toutatis is a tool that allows you to extract information from instagrams accounts such as e-mails, phone numbers and more
## 💡 Prerequisite
[Rust](https://www.rust-lang.org/tools/install) (latest stable version)

## 🛠️ Installation
### With Cargo (from crates.io)

```bash
cargo install toutatis
```

### With Github

```bash
git clone https://github.com/megadose/toutatis.git
cd toutatis/
cargo install --path .
```

## 📚 Usage:

### Find information from a username

```
toutatis -u username -s instagramsessionid
```

### Find information from an Instagram ID

```
toutatis -i instagramID -s instagramsessionid
```

## 📈 Example

```
Informations about     : xxxusernamexxx
Full Name              : xxxusernamesxx | userID : 123456789
Verified               : False | Is buisness Account : False
Is private Account     : False
Follower               : xxx | Following : xxx
Number of posts        : x
Number of tag in posts : x
External url           : http://example.com
IGTV posts             : x
Biography              : example biography
Public Email           : public@example.com
Public Phone           : +00 0 00 00 00 00
Obfuscated email       : me********s@examplemail.com
Obfuscated phone       : +00 0xx xxx xx 00
------------------------
Profile Picture        : https://scontent-X-X.cdninstagram.com/
```

## 📚 To retrieve the sessionID
![](https://files.catbox.moe/1rfi6j.png)

## Thank you to :

- [EyupErgin](https://github.com/eyupergin)
- [yazeed44](https://github.com/yazeed44)

## Support the Original Creator

If you'd like to donate to the original creator of this tool, you can visit the [original GitHub repository](https://github.com/megadose/toutatis) or use the following Bitcoin address:

BTC: 1FHDM49QfZX6pJmhjLE5tB2K6CaTLMZpXZ

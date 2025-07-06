use clap::Parser;
use color_eyre::eyre::Result;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use url::form_urlencoded;

#[derive(Parser)]
#[command(name = "toutatis")]
#[command(about = "Instagram information gathering tool")]
struct Cli {
    #[arg(short, long, help = "Instagram session ID")]
    sessionid: String,
    
    #[arg(short, long, help = "Username to search", conflicts_with = "id")]
    username: Option<String>,
    
    #[arg(short, long, help = "User ID to search", conflicts_with = "username")]
    id: Option<String>,
}

#[derive(Deserialize, Debug)]
struct UserResponse {
    data: UserData,
}

#[derive(Deserialize, Debug)]
struct UserData {
    user: UserInfo,
}

#[derive(Deserialize, Debug)]
struct UserInfo {
    id: String,
}

#[derive(Deserialize, Debug)]
struct InstagramUser {
    username: String,
    #[serde(rename = "userID")]
    user_id: Option<String>,
    full_name: String,
    is_verified: bool,
    is_business: bool,
    is_private: bool,
    follower_count: u32,
    following_count: u32,
    media_count: u32,
    external_url: Option<String>,
    total_igtv_videos: u32,
    biography: String,
    is_whatsapp_linked: bool,
    is_memorialized: bool,
    is_new_to_instagram: bool,
    public_email: Option<String>,
    public_phone_number: Option<String>,
    public_phone_country_code: Option<String>,
    hd_profile_pic_url_info: ProfilePicInfo,
}

#[derive(Deserialize, Debug)]
struct ProfilePicInfo {
    url: String,
}

#[derive(Deserialize, Debug)]
struct UserInfoResponse {
    user: InstagramUser,
}

#[derive(Deserialize, Debug)]
struct LookupResponse {
    obfuscated_email: Option<String>,
    obfuscated_phone: Option<String>,
    message: Option<String>,
}

async fn get_user_id(username: &str, session_id: &str) -> Result<String> {
    let client = Client::new();
    
    let url = format!("https://i.instagram.com/api/v1/users/web_profile_info/?username={}", username);
    
    let response = client
        .get(&url)
        .header("User-Agent", "iphone_ua")
        .header("x-ig-app-id", "936619743392459")
        .header("Cookie", format!("sessionid={}", session_id))
        .send()
        .await?;
    
    if response.status() == 404 {
        return Err(color_eyre::eyre::eyre!("User not found"));
    }
    
    let user_response: UserResponse = response.json().await?;
    Ok(user_response.data.user.id)
}

async fn get_user_info(user_id: &str, session_id: &str) -> Result<InstagramUser> {
    let client = Client::new();
    
    let url = format!("https://i.instagram.com/api/v1/users/{}/info/", user_id);
    
    let response = client
        .get(&url)
        .header("User-Agent", "Instagram 64.0.0.14.96")
        .header("Cookie", format!("sessionid={}", session_id))
        .send()
        .await?;
    
    if response.status() == 429 {
        return Err(color_eyre::eyre::eyre!("Rate limit exceeded"));
    }
    
    let mut user_info: UserInfoResponse = response.json().await?;
    user_info.user.user_id = Some(user_id.to_string());
    
    Ok(user_info.user)
}

async fn advanced_lookup(username: &str) -> Result<LookupResponse> {
    let client = Client::new();
    
    let data = json!({
        "q": username,
        "skip_recovery": "1"
    });
    
    let form_data = format!("signed_body=SIGNATURE.{}", 
        form_urlencoded::byte_serialize(data.to_string().as_bytes()).collect::<String>()
    );
    
    let response = client
        .post("https://i.instagram.com/api/v1/users/lookup/")
        .header("Accept-Language", "en-US")
        .header("User-Agent", "Instagram 101.0.0.15.120")
        .header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
        .header("X-IG-App-ID", "124024574287414")
        .header("Accept-Encoding", "gzip, deflate")
        .header("Host", "i.instagram.com")
        .header("Connection", "keep-alive")
        .header("Content-Length", form_data.len().to_string())
        .body(form_data)
        .send()
        .await?;
    
    let lookup_response: LookupResponse = response.json().await?;
    Ok(lookup_response)
}

fn format_phone_number(phone: &str, country_code: &str) -> String {
    format!("+{} {}", country_code, phone)
}

fn print_user_info(user: &InstagramUser) {
    println!("Informations about     : {}", user.username);
    if let Some(ref user_id) = user.user_id {
        println!("userID                 : {}", user_id);
    }
    println!("Full Name              : {}", user.full_name);
    println!("Verified               : {} | Is business Account : {}", user.is_verified, user.is_business);
    println!("Is private Account     : {}", user.is_private);
    println!("Follower               : {} | Following : {}", user.follower_count, user.following_count);
    println!("Number of posts        : {}", user.media_count);
    
    if let Some(ref external_url) = user.external_url {
        println!("External url           : {}", external_url);
    }
    
    println!("IGTV posts             : {}", user.total_igtv_videos);
    
    let formatted_bio = user.biography.lines()
        .collect::<Vec<&str>>()
        .join(&format!("\n{}", " ".repeat(25)));
    println!("Biography              : {}", formatted_bio);
    
    println!("Linked WhatsApp        : {}", user.is_whatsapp_linked);
    println!("Memorial Account       : {}", user.is_memorialized);
    println!("New Instagram user     : {}", user.is_new_to_instagram);
    
    if let Some(ref email) = user.public_email {
        println!("Public Email           : {}", email);
    }
    
    if let (Some(phone), Some(country_code)) = (&user.public_phone_number, &user.public_phone_country_code) {
        let formatted_phone = format_phone_number(phone, country_code);
        println!("Public Phone number    : {}", formatted_phone);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    
    let cli = Cli::parse();
    
    let user_id = if let Some(username) = &cli.username {
        get_user_id(username, &cli.sessionid).await?
    } else if let Some(id) = &cli.id {
        validate_id(id)?
    } else {
        return Err(color_eyre::eyre::eyre!("Either username or ID must be provided"));
    };
    
    let user_info = get_user_info(&user_id, &cli.sessionid).await?;
    print_user_info(&user_info);
    
    match advanced_lookup(&user_info.username).await {
        Ok(lookup_info) => {
            if let Some(ref message) = lookup_info.message {
                if message == "No users found" {
                    println!("The lookup did not work on this account");
                } else {
                    println!("{}", message);
                }
            } else {
                if let Some(ref obfuscated_email) = lookup_info.obfuscated_email {
                    println!("Obfuscated email       : {}", obfuscated_email);
                } else {
                    println!("No obfuscated email found");
                }
                
                if let Some(ref obfuscated_phone) = lookup_info.obfuscated_phone {
                    println!("Obfuscated phone       : {}", obfuscated_phone);
                } else {
                    println!("No obfuscated phone found");
                }
            }
        }
        Err(_) => {
            println!("Rate limit please wait a few minutes before you try again");
        }
    }
    
    println!("{}", "-".repeat(24));
    println!("Profile Picture        : {}", user_info.hd_profile_pic_url_info.url);
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_phone_number() {
        let result = format_phone_number("1234567890", "1");
        assert_eq!(result, "+1 1234567890");
        
        let result = format_phone_number("123456789", "33");
        assert_eq!(result, "+33 123456789");
    }

    #[test]
    fn test_cli_parsing() {
        let cli = Cli::try_parse_from(&["toutatis", "-s", "test_session", "-u", "test_user"]).unwrap();
        assert_eq!(cli.sessionid, "test_session");
        assert_eq!(cli.username, Some("test_user".to_string()));
        assert_eq!(cli.id, None);
    }

    #[test]
    fn test_cli_parsing_with_id() {
        let cli = Cli::try_parse_from(&["toutatis", "-s", "test_session", "-i", "12345"]).unwrap();
        assert_eq!(cli.sessionid, "test_session");
        assert_eq!(cli.username, None);
        assert_eq!(cli.id, Some("12345".to_string()));
    }

    #[test]
    fn test_cli_parsing_missing_required() {
        let result = Cli::try_parse_from(&["toutatis"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_parsing_conflicting_args() {
        let result = Cli::try_parse_from(&["toutatis", "-s", "test_session", "-u", "user", "-i", "123"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_user_response_deserialization() {
        let json = r#"{"data": {"user": {"id": "123456789"}}}"#;
        let result: Result<UserResponse, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        let user_response = result.unwrap();
        assert_eq!(user_response.data.user.id, "123456789");
    }

    #[test]
    fn test_lookup_response_deserialization() {
        let json = r#"{"obfuscated_email": "t***@example.com", "obfuscated_phone": "+1 ***-***-1234"}"#;
        let result: Result<LookupResponse, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        let lookup_response = result.unwrap();
        assert_eq!(lookup_response.obfuscated_email, Some("t***@example.com".to_string()));
        assert_eq!(lookup_response.obfuscated_phone, Some("+1 ***-***-1234".to_string()));
    }

    #[test]
    fn test_lookup_response_with_message() {
        let json = r#"{"message": "No users found"}"#;
        let result: Result<LookupResponse, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        let lookup_response = result.unwrap();
        assert_eq!(lookup_response.message, Some("No users found".to_string()));
        assert_eq!(lookup_response.obfuscated_email, None);
        assert_eq!(lookup_response.obfuscated_phone, None);
    }

    #[test]
    fn test_instagram_user_deserialization() {
        let json = r#"{
            "username": "testuser",
            "full_name": "Test User",
            "is_verified": false,
            "is_business": false,
            "is_private": false,
            "follower_count": 100,
            "following_count": 50,
            "media_count": 25,
            "external_url": "https://example.com",
            "total_igtv_videos": 5,
            "biography": "Test bio",
            "is_whatsapp_linked": false,
            "is_memorialized": false,
            "is_new_to_instagram": false,
            "public_email": "test@example.com",
            "public_phone_number": "1234567890",
            "public_phone_country_code": "1",
            "hd_profile_pic_url_info": {"url": "https://example.com/pic.jpg"}
        }"#;
        
        let result: Result<InstagramUser, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "testuser");
        assert_eq!(user.full_name, "Test User");
        assert_eq!(user.follower_count, 100);
        assert_eq!(user.public_email, Some("test@example.com".to_string()));
        assert_eq!(user.hd_profile_pic_url_info.url, "https://example.com/pic.jpg");
    }

    #[tokio::test]
    async fn test_invalid_id_validation() {
        let result = validate_id("not_a_number");
        assert!(result.is_err());
        
        let result = validate_id("123456789");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "123456789");
    }

    #[tokio::test]
    async fn test_get_user_id_404_error() {
        let mut server = mockito::Server::new_async().await;
        let mock = server.mock("GET", "/api/v1/users/web_profile_info/?username=nonexistent")
            .with_status(404)
            .create_async()
            .await;

        let base_url = server.url();
        let result = get_user_id_with_base_url("nonexistent", "test_session", &base_url).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("User not found"));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_user_info_rate_limit() {
        let mut server = mockito::Server::new_async().await;
        let mock = server.mock("GET", "/api/v1/users/123456789/info/")
            .with_status(429)
            .create_async()
            .await;

        let base_url = server.url();
        let result = get_user_info_with_base_url("123456789", "test_session", &base_url).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Rate limit exceeded"));
        mock.assert_async().await;
    }
}

fn validate_id(id: &str) -> Result<String> {
    if id.parse::<u64>().is_err() {
        return Err(color_eyre::eyre::eyre!("Invalid ID format"));
    }
    Ok(id.to_string())
}

#[cfg(test)]
async fn get_user_id_with_base_url(username: &str, session_id: &str, base_url: &str) -> Result<String> {
    let client = Client::new();
    
    let url = format!("{}/api/v1/users/web_profile_info/?username={}", base_url, username);
    
    let response = client
        .get(&url)
        .header("User-Agent", "iphone_ua")
        .header("x-ig-app-id", "936619743392459")
        .header("Cookie", format!("sessionid={}", session_id))
        .send()
        .await?;
    
    if response.status() == 404 {
        return Err(color_eyre::eyre::eyre!("User not found"));
    }
    
    let user_response: UserResponse = response.json().await?;
    Ok(user_response.data.user.id)
}

#[cfg(test)]
async fn get_user_info_with_base_url(user_id: &str, session_id: &str, base_url: &str) -> Result<InstagramUser> {
    let client = Client::new();
    
    let url = format!("{}/api/v1/users/{}/info/", base_url, user_id);
    
    let response = client
        .get(&url)
        .header("User-Agent", "Instagram 64.0.0.14.96")
        .header("Cookie", format!("sessionid={}", session_id))
        .send()
        .await?;
    
    if response.status() == 429 {
        return Err(color_eyre::eyre::eyre!("Rate limit exceeded"));
    }
    
    let mut user_info: UserInfoResponse = response.json().await?;
    user_info.user.user_id = Some(user_id.to_string());
    
    Ok(user_info.user)
}
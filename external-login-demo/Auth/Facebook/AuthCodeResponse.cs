namespace external_login_demo.Auth
{
    public class AuthCodeResponse
    {
        public string? Access_token { get; set; }
        public string? Token_type { get; set; }
        public int Expires_in { get; set; }
    }
}

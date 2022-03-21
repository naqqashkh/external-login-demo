namespace external_login_demo.Auth
{
    public class AuthCodeRequest
    {
        public string? code { get; set; }
        public string? redirect_uri { get; set; }
        public string grant_type { get; set; } = "authorization_code";
        public string? client_id { get; set; }
        public string? client_secret { get; set; }
    }
}

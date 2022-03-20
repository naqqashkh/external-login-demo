namespace external_login_demo.Auth
{
    public class AuthCodeRequest : AuthCodeModel
    {
        public string grant_type { get; set; } = "authorization_code";
        public string? client_id { get; set; }
        public string? client_secret { get; set; }
    }
}

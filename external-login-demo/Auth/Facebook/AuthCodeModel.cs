namespace external_login_demo.Auth
{
    public class AuthCodeModel
    {
        public string code { get; set; } = string.Empty;
        public string redirect_uri { get; set; } = string.Empty;
    }
}

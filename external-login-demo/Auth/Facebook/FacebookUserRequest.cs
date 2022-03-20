namespace external_login_demo.Auth
{
    public class FacebookUserRequest
    {
        public string? access_token { get; set; }
        public string fields { get; set; } = "name,email";
    }
}

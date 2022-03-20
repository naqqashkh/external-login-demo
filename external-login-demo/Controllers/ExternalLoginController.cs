using external_login_demo.Auth;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace external_login_demo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ExternalLoginController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public ExternalLoginController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        [HttpPost("facebook")]
        public async Task<IActionResult> Facebook([FromBody] AuthCodeModel data)
        {
            try
            {
                FacebookUserResponse facebookUser;
                string accessToken;

                //Exchanging for an access token
                using (var httpClient = new HttpClient())
                {
                    var content = new AuthCodeRequest()
                    {
                        code = data.code,
                        redirect_uri = data.redirect_uri,
                        client_id = _configuration["Authentication:Facebook:AppId"],
                        client_secret = _configuration["Authentication:Facebook:AppSecret"]
                    };
                    
                    using (var response = await httpClient.PostAsJsonAsync("https://graph.facebook.com/v2.6/oauth/access_token", content))
                    {
                        if (!response.IsSuccessStatusCode)
                            return StatusCode(Convert.ToInt32(response.StatusCode), new Response { Status = "Error", Message = response.ReasonPhrase });

                        string apiResponse = await response.Content.ReadAsStringAsync();
                        accessToken = JsonConvert.DeserializeObject<AuthCodeResponse>(apiResponse).Access_token;
                    }
                }

                //Get the user details using access token.
                using (var httpClient = new HttpClient())
                {
                    var content = new FacebookUserRequest()
                    {
                        access_token = accessToken,
                    };

                    using (var response = await httpClient.PostAsJsonAsync("https://graph.facebook.com/v2.6/me", content))
                    {
                        if (!response.IsSuccessStatusCode)
                            return StatusCode(Convert.ToInt32(response.StatusCode), new Response { Status = "Error", Message = response.ReasonPhrase });

                        string apiResponse = await response.Content.ReadAsStringAsync();
                        facebookUser = JsonConvert.DeserializeObject<FacebookUserResponse>(apiResponse);
                    }
                }

                //Find User
                var user = await _userManager.FindByEmailAsync(facebookUser.email);

                //If User not found then create user.
                if (user == null)
                {
                    user = new IdentityUser()
                    {
                        SecurityStamp = Guid.NewGuid().ToString(),
                        UserName = facebookUser.email,
                        Email = facebookUser.email,
                    };

                    var result = await _userManager.CreateAsync(user);

                    if (!result.Succeeded)
                        return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

                    result = await _userManager.AddLoginAsync(user, new UserLoginInfo("Facebook", facebookUser.id, "Facebook"));

                    if (!result.Succeeded)
                        return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
                }

                var loginInfo = await _userManager.FindByLoginAsync("Facebook", facebookUser.id);

                if (loginInfo is null)
                    return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Association with Facebook of this user not found." });

                //Create Claims and Token

                return Ok(new Response { Status = "Success", Message = "Authorized" });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("google/{tokenId}")]
        public async Task<IActionResult> Google(string tokenId)
        {
            try
            {
                var payload = GoogleJsonWebSignature.ValidateAsync(tokenId, new GoogleJsonWebSignature.ValidationSettings()).Result;
                
                //Find User
                var user = await _userManager.FindByEmailAsync(payload.Email);

                //If User not found then create user.
                if (user == null)
                {
                    user = new IdentityUser()
                    {
                        SecurityStamp = Guid.NewGuid().ToString(),
                        UserName = payload.Name,
                        Email = payload.Email,
                    };

                    var result = await _userManager.CreateAsync(user);

                    if (!result.Succeeded)
                        return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

                    //The provider key can be changed if desirable
                    result = await _userManager.AddLoginAsync(user, new UserLoginInfo("Google", payload.Email, "Google"));

                    if (!result.Succeeded)
                        return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
                }

                var loginInfo = await _userManager.FindByLoginAsync("Google", payload.Email);

                if (loginInfo is null)
                    return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Association with Google of this user not found." });

                return Ok(new Response { Status = "Success", Message = "Authorized" });

                //var claims = new[]
                //{
                //    new Claim(JwtRegisteredClaimNames.Sub, Security.Encrypt(AppSettings.appSettings.JwtEmailEncryption,user.email)),
                //    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                //};

                //var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(AppSettings.appSettings.JwtSecret));
                //var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                //var token = new JwtSecurityToken(String.Empty,
                //  String.Empty,
                //  claims,
                //  expires: DateTime.Now.AddSeconds(55 * 60),
                //  signingCredentials: creds);
                //return Ok(new
                //{
                //    token = new JwtSecurityTokenHandler().WriteToken(token)
                //});
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}

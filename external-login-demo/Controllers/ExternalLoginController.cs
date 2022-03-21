using external_login_demo.Auth;
using external_login_demo.Auth.Google;
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

        [HttpPost("facebook/{authCode}")]
        public async Task<IActionResult> Facebook(string authCode)
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
                        code = authCode,
                        redirect_uri = _configuration["Authentication:Facebook:RedirectUri"],
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

                //Get the user details from Facebook using access token.
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
                }

                var loginInfo = await _userManager.FindByLoginAsync("Facebook", facebookUser.id);

                if (loginInfo is null)
                {
                    var result = await _userManager.AddLoginAsync(user, new UserLoginInfo("Facebook", facebookUser.id, "Facebook"));

                    if (!result.Succeeded)
                        return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

                    loginInfo = await _userManager.FindByLoginAsync("Facebook", facebookUser.id);
                }

                //Create Claims and Token

                return Ok(new Response { Status = "Success", Message = "Authorized" });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("google/{accessToken}")]
        public async Task<IActionResult> Google(string accessToken)
        {
            try
            {
                GoogleUserResponse googleUser;

                //Get user from Google using access token
                using (var httpClient = new HttpClient())
                {
                    using (var response = await httpClient.GetAsync("https://www.googleapis.com/oauth2/v1/userinfo?access_token=" + accessToken))
                    {
                        if (!response.IsSuccessStatusCode)
                            return StatusCode(Convert.ToInt32(response.StatusCode), new Response { Status = "Error", Message = response.ReasonPhrase });

                        string apiResponse = await response.Content.ReadAsStringAsync();
                        googleUser = JsonConvert.DeserializeObject<GoogleUserResponse>(apiResponse);
                    }
                }

                //Find User in database
                var user = await _userManager.FindByEmailAsync(googleUser.Email);

                //If User not found then create user.
                if (user == null)
                {
                    user = new IdentityUser()
                    {
                        SecurityStamp = Guid.NewGuid().ToString(),
                        UserName = googleUser.Email,
                        Email = googleUser.Email,
                    };

                    var result = await _userManager.CreateAsync(user);

                    if (!result.Succeeded)
                        return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
                }

                var loginInfo = await _userManager.FindByLoginAsync("Google", googleUser.Email);

                if (loginInfo is null)
                {
                    var result = await _userManager.AddLoginAsync(user, new UserLoginInfo("Google", googleUser.Id, "Google"));

                    if (!result.Succeeded)
                        return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

                    loginInfo = await _userManager.FindByLoginAsync("Google", googleUser.Email);
                }

                return Ok(new Response { Status = "Success", Message = "Authorized" });

                //Create claims and token
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}

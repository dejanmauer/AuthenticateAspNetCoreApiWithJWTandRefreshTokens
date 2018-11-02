# ASP.NET Core 2.1 API Authentication with JWT tokens (bearer)

Nothing is easy anymore with .NET Core :) 

What used to be a feature selection in the old days, now requires quite some configuration code. 

This project is a boilerplate I've created primary for myself - so the next time I will be able to quickly jump to work on API without reading all of the internet under the search terms of "bearer authentication .NET Core 2.1", "JWT authentiction .NET Core API", "Use Identity Core 2.1 with JWT tokens" or even "Where the hell are hidden Identity views and controllers".

# What is this project all about?
The aim of this project is to secure Web API access, so only authorized users will be able to call API methods. We would like to use [Authorize] attribute in controller to protect resources from unauthorized users. Something like this:

```csharp
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace testapi.Controllers
{
	[Route("api/[controller]/[action]")]
	[ApiController]

	public class ValuesController : ControllerBase
	{
		// GET api/values
		[HttpGet]
		public ActionResult<IEnumerable<string>> Get()
		{
			return new string[] { "value1", "value2" };
		}

		[Authorize]
		[HttpGet]
		public ActionResult<IEnumerable<string>> GetAuthenticated()
		{
			return new string[] { "value1", "value2", User.Identity.Name };
		}
	}
}
```

In the controller above, anybody can call Get action and receive the results, while GetAuthenticated() action returns results only if the user is authenticated.

And how to authenticate user?

One of the most popular way to secure API endpoints is token authentication (also known as bearer authentication). Let's look at the workflow:

- important: SSL (HTTPS) must be used when dealing with token authentication!
- user sends credentials to token provider API - login method (for example: www.mysite.com/api/token/login?username=dejan&password=Pa$$1234)
- application checks if the user exists and the provided password is correct. In our case we depend on the Asp.Net Core Identity with identity information stored on SQL Server.
- if user is found and password is correct (which is done by comparing password hashes) than the JWT token gets created.
- JWT token consists of user credentials. The data are digitally signed, so that receiver can always check for authenticy.
- JWT token is send back to the user. This token must be sent in the header of every call to protected API actions.

When the token is issued it has information about validity. User tokens are usually valid from several minutes to several days, depending on the application. Please be aware that anybody who might intercept the token can do nasty things and there is no easy way to revoke just one token! That is why shorter tokens are considered more secure.

This brings us to the next question. If tokens with short validity are preferable, how to renew token after the expiriation? Ask user again to enter credentials? Not the best approach... One way to overcome the issue is to issue one time refresh token at the time user receives access token. This token is then used - combined with expired access token - to automatically issue new access token without asking user for their credentials.

# How to access API?
First of all, you need to authenticate user and receive tokens (JWT access token and refresh token). This is done by calling /account/login action, with provided username (email) and password.

```csharp
var client = new RestClient("https://localhost:44321/account/login");
var request = new RestRequest(Method.POST);
request.AddHeader("cache-control", "no-cache");
request.AddHeader("content-type", "application/x-www-form-urlencoded");
request.AddParameter("application/x-www-form-urlencoded", "email=dejan.mauer%40gmail.com&password=MySecretPassword$$", ParameterType.RequestBody);
IRestResponse response = client.Execute(request);
```
In return you will receive two tokens. You will probably store both locally and use JWT access token in the header of the request accessing protected resources (or actions or api endpoints). Consider this example:

```csharp
var client = new RestClient("https://localhost:44321/api/values/getauthenticated");
var request = new RestRequest(Method.GET);
request.AddHeader("cache-control", "no-cache");
request.AddHeader("authorization", "bearer eyJhbGciOi ... rest of your token ... N-zJLDc20");
IRestResponse response = client.Execute(request);
```

Specify token in header's 'authorization' field. Remember to put word 'bearer ' before the token!

Since JWT access token has short validity, you might get response code 401 (Not Authorized) with status code of 'www-authenticate' set to 'Bearer error="invalid_token", error_description="The token is expired"'. This means you need to get new token, as the old one is expired.

To do so, call /account/refresh action with two parameters. First one is expired JWT token and the second one is the refresh token. This action returns new token, as well as new refresh token (remember, refresh token is only valid once).

## JWT (JSON Web Tokens)
JWT (JSON web token) has become popular in web development. It is an open standard for transmiting data as a JSON object in a secure way. The data transmitting using JWT between parties are digitally signed so that it can be easily verified and trusted.

## Start a new project
You can start a blank project from Visual Studio 2017 / File / New / Project and then select ASP.NET Core Web Application. When dialog opens, select API and make sure the authentication is set to "No authentication". This sample works with ASP.NET Core version 2.1.

In case you are a command line, power user, keyboard ninja, you can try to create new project with:

dotnet new webapi -n ApiTokenExample (insert here your project name)

## Startup.cs
The most of 'intelectual work' was used configuring Startup.cs.

First, we have to register JWT authentication schema by using "AddAuthentication" in ConfigureServices method.

You know, by default no external client can use your API, so you must allow calls from other clients. This is called CORS settings. Be aware, I have set the project that any client can use APIs.
```csharp
			services.AddCors(options => options.AddPolicy("Cors", builder =>
			{
				builder
				.AllowAnyOrigin()
				.AllowAnyMethod()
				.AllowAnyHeader();
			}));
```
Then MVC service gets configured:

```csharp
services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);

Next step is to configure database context (Entity Core) and Identity Core.
			services.AddDbContext<ApplicationDbContext>(options =>
				options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

			services.AddIdentity<IdentityUser, IdentityRole>()
				.AddEntityFrameworkStores<ApplicationDbContext>();
 ```
 
Connection string is stored in the setting files - appsetings.json.

After that there is some dependency injection mambo jambo.

At the end, there is configuration for Authentication with JWT:

```csharp
services.AddAuthentication(options =>
			{
				options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
				options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
			}).AddJwtBearer(options =>
			{
				options.RequireHttpsMetadata = false;
				options.SaveToken = true;

				options.TokenValidationParameters = new TokenValidationParameters
				{
					ValidateAudience = false,
					ValidateIssuer = false,
					ValidateIssuerSigningKey = true,
					IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Tokens:Key"])),
					ValidateLifetime = true,
					ClockSkew = TimeSpan.Zero 
				};

				options.Events = new JwtBearerEvents
				{
					OnAuthenticationFailed = context =>
					{
						if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
						{
							context.Response.Headers.Add("Token-Expired", "true");
						}
						return Task.CompletedTask;
					}
				};
			});
```

Please note, that I decided to implement token refresh mechanism. This means that after the token validity expires, it is possible to get new access token without user to enter username/password again.

```csharp
		public void Configure(IApplicationBuilder app, IHostingEnvironment env)
		{
			if (env.IsDevelopment())
			{
				app.UseDeveloperExceptionPage();
			}
			else
			{
				app.UseHsts();
			}

			app.UseCors("Cors");
			app.UseAuthentication();

			app.UseHttpsRedirection();
			app.UseMvc();
		}
```
    
Insert
app.UseAuthentication in Configure method of Startup.cs

## Generate JWT token

```csharp
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace testapi.Services
{
    public class TokenService : ITokenService
    {
        private readonly IConfiguration _configuration;

        public TokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

		public string GenerateAccessToken(IEnumerable<Claim> claims)
		{
			var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Tokens:Key"]));
			var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

			var jwt = new JwtSecurityToken(
				issuer: _configuration["Tokens:Issuer"],
				audience: _configuration["Tokens:Issuer"],
				claims: claims, //the user's claims, for example new Claim[] { new Claim(ClaimTypes.Name, "The username"), //... 
				notBefore: DateTime.UtcNow,
				expires: DateTime.UtcNow.AddSeconds(20),
				signingCredentials: credentials
			);

			return new JwtSecurityTokenHandler().WriteToken(jwt); //the method is called WriteToken but returns a string
		}

		public string GenerateRefreshToken()
		{
			var randomNumber = new byte[32];
			using (var rng = RandomNumberGenerator.Create())
			{
				rng.GetBytes(randomNumber);
				return Convert.ToBase64String(randomNumber);
			}
		}

		public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false, //you might want to validate the audience and issuer depending on your use case
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Tokens:Key"])),
                ValidateLifetime = false //here we are saying that we don't care about the token's expiration date
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }
	}
}
```

## Account controller
This constoller is used to register new user, retrieve token (login) and to refresh token.
```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using testapi.Data;
using testapi.Models;
using testapi.Models.AccountViewModels;
using testapi.Services;

namespace DualAuthCore.Controllers
{
	[Authorize]
	[Route("[controller]/[action]")]
	public class AccountController : Controller
	{
		private readonly UserManager<IdentityUser> _userManager;
		private readonly SignInManager<IdentityUser> _signInManager;
		private readonly IEmailSender _emailSender;
		private readonly ILogger _logger;
		private readonly IConfiguration _config;
		private readonly ApplicationDbContext _context;
		private readonly IPasswordHasher _passwordHasher;
		private readonly ITokenService _tokenService;

		public AccountController(
			UserManager<IdentityUser> userManager,
			SignInManager<IdentityUser> signInManager,
			IEmailSender emailSender,
			ILogger<AccountController> logger,
			IConfiguration config,
			ApplicationDbContext context,
			IPasswordHasher passwordHasher,
			ITokenService tokenService)
		{
			_userManager = userManager;
			_signInManager = signInManager;
			_emailSender = emailSender;
			_logger = logger;
			_config = config;
			_context = context;
			_passwordHasher = passwordHasher;
			_tokenService = tokenService;
		}

		[HttpPost]
		[AllowAnonymous]
		public async Task<IActionResult> Register(string username, string password)
		{

			var user = new IdentityUser { UserName = username, Email = username };

			user.EmailConfirmed = true;

			var result = await _userManager.CreateAsync(user, password);
			if (result.Succeeded)
			{
				_logger.LogInformation("User created a new account with password.");

				// add user 
				var refreshUser = _context.UserRefreshTokens.SingleOrDefault(u => u.Username == username);
				if (refreshUser != null) return StatusCode(409);

				_context.UserRefreshTokens.Add(new UserRefreshToken
				{
					Username = username,
					Password = _passwordHasher.GenerateIdentityV3Hash(password)
				});

				await _context.SaveChangesAsync();
				refreshUser = _context.UserRefreshTokens.SingleOrDefault(u => u.Username == username);
				return Ok(refreshUser);
			}

			return BadRequest("Could not register user.");
		}

		[HttpPost]
		[AllowAnonymous]
		public async Task<IActionResult> RefreshToken(string authenticationToken, string refreshToken)
		{
			var principal = _tokenService.GetPrincipalFromExpiredToken(authenticationToken);
			var username = principal.Identity.Name; //this is mapped to the Name claim by default

			var user = _context.UserRefreshTokens.SingleOrDefault(u => u.Username == username);
			if (user == null || user.RefreshToken != refreshToken) return BadRequest();

			var newJwtToken = _tokenService.GenerateAccessToken(principal.Claims);
			var newRefreshToken = _tokenService.GenerateRefreshToken();

			user.RefreshToken = newRefreshToken;
			await _context.SaveChangesAsync();

			return new ObjectResult(new
			{
				authenticationToken = newJwtToken,
				refreshToken = newRefreshToken
			});
		}

		[AllowAnonymous]
		[HttpPost]
		public async Task<IActionResult> Login(LoginViewModel model)
		{
			if (ModelState.IsValid)
			{
				var user = await _userManager.FindByEmailAsync(model.Email);

				if (user != null)
				{
					var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
					if (result.Succeeded)
					{

						var claims = new[]
						{
							new Claim(JwtRegisteredClaimNames.Sub, user.Email),
							new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
							new Claim(JwtRegisteredClaimNames.Email, user.Email),
							new Claim(ClaimTypes.Name, user.Email)
						};

						var token = _tokenService.GenerateAccessToken(claims);
						var newRefreshToken = _tokenService.GenerateRefreshToken();

						var userRefreshToken = _context.UserRefreshTokens.Where(urt => urt.Username == user.Email).FirstOrDefault();
						userRefreshToken.RefreshToken = newRefreshToken;
						await _context.SaveChangesAsync();

						return new ObjectResult(new
						{
							authenticationToken = token,
							refreshToken = newRefreshToken
						});
					}
				}
			}

			return BadRequest("Could not create token");
		}
	}
}
```

## Protect APIs
Once all set, you can protect APIs with the [Authorize] annotation.

```csharp
namespace testapi.Controllers
{
	[Route("api/[controller]/[action]")]
	[ApiController]

	public class ValuesController : ControllerBase
	{
		// GET api/values
		[HttpGet]
		public ActionResult<IEnumerable<string>> Get()
		{
			return new string[] { "value1", "value2" };
		}

		[Authorize]
		[HttpGet]
		public ActionResult<IEnumerable<string>> GetAuthenticated()
		{
			return new string[] { "value1", "value2", User.Identity.Name };
		}
	}
}
```

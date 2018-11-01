using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using testapi.Models;
using testapi.Models.AccountViewModels;
using testapi.Services;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using System.Text;
using testapi.Extensions;
using testapi.Data;

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
using DualAuthCore.Controllers;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using testapi.Controllers;

namespace testapi.Extensions
{
	public static class UrlHelperExtensions
	{
		public static string EmailConfirmationLink(this IUrlHelper urlHelper, string userId, string code, string scheme)
		{
			throw new NotImplementedException();
			//return urlHelper.Action(
			//	action: nameof(AccountController.ConfirmEmail),
			//	controller: "Account",
			//	values: new { userId, code },
			//	protocol: scheme);
		}

		public static string ResetPasswordCallbackLink(this IUrlHelper urlHelper, string userId, string code, string scheme)
		{
			throw new NotImplementedException();
			//return urlHelper.Action(
			//	action: nameof(AccountController.ResetPassword),
			//	controller: "Account",
			//	values: new { userId, code },
			//	protocol: scheme);
		}
	}
}
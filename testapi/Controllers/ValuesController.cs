using System;
using System.Collections.Generic;
using System.Linq;
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

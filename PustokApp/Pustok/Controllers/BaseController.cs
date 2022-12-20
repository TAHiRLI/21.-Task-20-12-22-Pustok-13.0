using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion.Internal;
using System.Security.Claims;

namespace Pustok.Controllers
{
	public class BaseController : Controller
	{
		protected string UserId => User.FindFirstValue(ClaimTypes.NameIdentifier);
	}
}

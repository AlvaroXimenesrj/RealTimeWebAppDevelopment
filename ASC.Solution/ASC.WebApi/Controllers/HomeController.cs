using ASC.WebApi.Configuration;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace ASC.WebApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class HomeController : ControllerBase
    {       

        private readonly ILogger<HomeController> _logger;
        private ApplicationSettings _env;

        public HomeController(ILogger<HomeController> logger, IOptions<ApplicationSettings> env)
        {
            _logger = logger;
            _env = env.Value;
        }

        [HttpGet]
        public async Task<IActionResult> Get()
        {
            return Ok("Hello World: "+ _env.ApplicationTitle);
        }
    }
}
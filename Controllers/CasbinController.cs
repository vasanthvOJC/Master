using Microsoft.AspNetCore.Mvc;
using Casbin.Models.Casbin;

namespace Casbin.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class CasbinController : ControllerBase
    {

        private readonly ILogger<CasbinController> _logger;

        public CasbinController(ILogger<CasbinController> logger)
        {
            _logger = logger;
        }
        //public IActionResult Index()
        //{
           
        //}

        [HttpPost("Authorize")]
        public bool Casbin(CasbinModelRequest request)
        {
            Business.Casbin casbin = new();
            bool response = casbin.casbin(request);
            Console.WriteLine(response);
            return response;
        }

    }
}

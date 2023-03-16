namespace Casbin.Models.Casbin
{
    public class CasbinModelRequest
    {
        public subject Subject { get; set; }
        public string? Domain { get; set; }
        public string Object { get; set; } 
        public string Action { get; set; } 
        public string Model { get; set; }
    }

    public class subject
    {
        //public string Author { get; set; }
        //public string Experience { get; set; }
        //public string Pricefield { get; set; }
        public string Age { get; set; }
    }
}

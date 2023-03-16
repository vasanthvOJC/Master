namespace Casbin
{
    public class Helper
    {
        public string DefaultConnection { get; set; }

        public Helper(string configSection, string configFilePath = "appSettings.json")
        {
            LoadSettings(configSection, configFilePath);
        }

        public void LoadSettings(string configSection, string configFilePath)
        {
            var builder = new ConfigurationBuilder().AddJsonFile(configFilePath).Build();
            builder.GetSection(configSection).Bind(this);
        }
    }
}

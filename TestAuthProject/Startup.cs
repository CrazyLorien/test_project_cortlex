using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(TestAuthProject.Startup))]
namespace TestAuthProject
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}

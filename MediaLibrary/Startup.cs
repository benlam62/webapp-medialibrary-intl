using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(MediaLibrary.Startup))]
namespace MediaLibrary
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}

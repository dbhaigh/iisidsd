using iisidsd.Models;

namespace iisidsd.Iis;

public interface IIisAutoDenyService
{
    void Apply(SecurityEvent securityEvent);
}

using iisidsd.Models;

namespace iisidsd.Detection;

public interface ISuspiciousActivityDetector
{
    SecurityEvent? Analyze(SecurityEvent webEvent);
}

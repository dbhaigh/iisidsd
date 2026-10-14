namespace iisidsd.Iis;

public interface IAppCmdRunner
{
    (bool Success, string Output, string Error) Run(params string[] arguments);
}

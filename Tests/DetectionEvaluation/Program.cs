using System.Text.Json;
using iisidsd.DetectionEvaluation;
using iisidsd.Models;
using Microsoft.Extensions.Configuration;

var arguments = ParseArguments(args);
if (arguments.Help)
{
    Console.WriteLine("Usage: dotnet run --project Tests/DetectionEvaluation -- --fixture <path> [--config <path>] [--compare <report>] [--output <path>]");
    return 0;
}

try
{
    var configuration = new ConfigurationBuilder()
        .AddJsonFile(Path.GetFullPath(arguments.ConfigPath), optional: false, reloadOnChange: false)
        .Build();
    var options = configuration.GetSection(DetectionOptions.SectionName).Get<DetectionOptions>()
        ?? throw new InvalidDataException("The configuration file has no Detection section.");
    var report = DetectionEvaluationRunner.Evaluate(arguments.FixturePath, options);
    if (arguments.ComparePath is not null)
    {
        var baseline = JsonSerializer.Deserialize<EvaluationReport>(File.ReadAllText(arguments.ComparePath), new JsonSerializerOptions(JsonSerializerDefaults.Web))
            ?? throw new InvalidDataException("Comparison report is empty or invalid JSON.");
        report = report with { Comparison = EvaluationComparison.Compare(baseline, report) };
    }

    var json = JsonSerializer.Serialize(report, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true }) + Environment.NewLine;

    if (arguments.OutputPath is null)
    {
        Console.Write(json);
    }
    else
    {
        var outputPath = Path.GetFullPath(arguments.OutputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        File.WriteAllText(outputPath, json);
        Console.WriteLine($"Evaluation report written to {outputPath}");
    }

    return 0;
}
catch (Exception exception)
{
    Console.Error.WriteLine($"Detection evaluation failed: {exception.Message}");
    return 1;
}

static (string FixturePath, string ConfigPath, string? ComparePath, string? OutputPath, bool Help) ParseArguments(string[] arguments)
{
    string? fixturePath = null;
    string configPath = "appsettings.json";
    string? comparePath = null;
    string? outputPath = null;
    var help = false;

    for (var index = 0; index < arguments.Length; index++)
    {
        switch (arguments[index])
        {
            case "--fixture" when index + 1 < arguments.Length:
                fixturePath = arguments[++index];
                break;
            case "--config" when index + 1 < arguments.Length:
                configPath = arguments[++index];
                break;
            case "--compare" when index + 1 < arguments.Length:
                comparePath = arguments[++index];
                break;
            case "--output" when index + 1 < arguments.Length:
                outputPath = arguments[++index];
                break;
            case "--help":
            case "-h":
                help = true;
                break;
            default:
                throw new ArgumentException($"Unknown or incomplete argument '{arguments[index]}'.");
        }
    }

    if (!help && string.IsNullOrWhiteSpace(fixturePath))
    {
        throw new ArgumentException("--fixture is required.");
    }

    return (fixturePath ?? string.Empty, configPath, comparePath, outputPath, help);
}
using System.Windows;
using Microsoft.Win32;
using Antivirus.Core.Services;
using Antivirus.Core.Security;

namespace Antivirus.UI;

public partial class MainWindow : Window
{
    private readonly IFileScanner _scanner = new YaraScanner();
    private readonly QuarantineService _quarantine = new();

    public MainWindow()
    {
        InitializeComponent();
    }

    private void PickFileButton_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Выберите файл для сканирования"
        };

        if (dlg.ShowDialog(this) == true)
        {
            try
            {
                var result = _scanner.ScanFile(dlg.FileName);
                ResultTextBox.Text = $"Файл: {result.FilePath}\nВредоносный: {result.IsMalicious}\nПричина: {result.Reason}";
            }
            catch (Exception ex)
            {
                ResultTextBox.Text = ex.ToString();
            }
        }
    }
    private void ScanDirectoryButton_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog
        {
            Title = "Выберите папку для сканирования"
        };

        if (dlg.ShowDialog(this) == true)
        {
            try
            {
                var results = _scanner.ScanDirectory(dlg.FolderName);
                var maliciousFiles = results.Where(r => r.IsMalicious).ToList();
                var cleanFiles = results.Where(r => !r.IsMalicious).ToList();

                ResultTextBox.Text = $"Сканирование завершено: {results.Count()} файлов\n" +
                                   $"Вредоносных: {maliciousFiles.Count}\n" +
                                   $"Чистых: {cleanFiles.Count}\n\n";

                if (maliciousFiles.Any())
                {
                    ResultTextBox.Text += "Обнаруженные угрозы:\n";
                    foreach (var result in maliciousFiles)
                    {
                        ResultTextBox.Text += $"{result.FilePath}: {result.Reason}\n";
                    }
                }
                else
                {
                    ResultTextBox.Text += "Угроз не обнаружено.";
                }
            }
            catch (Exception ex)
            {
                ResultTextBox.Text = ex.ToString();
            }
        }
    }

    private void OpenQuarantineButton_Click(object sender, RoutedEventArgs e)
    {
        var wnd = new QuarantineWindow();
        wnd.Owner = this;
        wnd.ShowDialog();
    }

    private void QuarantineFileButton_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Выберите файл для помещения в карантин"
        };

        if (dlg.ShowDialog(this) == true)
        {
            try
            {
                var id = _quarantine.MoveToQuarantine(dlg.FileName, note: "manual");
                MessageBox.Show(this, $"Файл помещён в карантин. Id={id}", "Карантин");
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Ошибка карантина");
            }
        }
    }
}
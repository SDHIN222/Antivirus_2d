using System.Collections.ObjectModel;
using System.Windows;
using Antivirus.Core.Security;

namespace Antivirus.UI;

public partial class QuarantineWindow : Window
{
	private readonly QuarantineService _service = new();
	public ObservableCollection<QuarantineService.QuarantineRow> Items { get; } = new();

	public QuarantineWindow()
	{
		InitializeComponent();
		GridItems.ItemsSource = Items;
		LoadData();
	}

	private void LoadData()
	{
		Items.Clear();
		foreach (var row in _service.List())
			Items.Add(row);
	}

	private void RefreshButton_Click(object sender, RoutedEventArgs e)
	{
		LoadData();
	}

	private void RestoreButton_Click(object sender, RoutedEventArgs e)
	{
		if (GridItems.SelectedItem is QuarantineService.QuarantineRow row)
		{
			try
			{
				_service.Restore(row.Id);
				LoadData();
			}
			catch (Exception ex)
			{
				MessageBox.Show(this, ex.Message, "Ошибка восстановления");
			}
		}
	}

	private void DeleteButton_Click(object sender, RoutedEventArgs e)
	{
		if (GridItems.SelectedItem is QuarantineService.QuarantineRow row)
		{
			if (MessageBox.Show(this, "Удалить файл навсегда?", "Подтверждение", MessageBoxButton.YesNo) == MessageBoxResult.Yes)
			{
				try
				{
					_service.DeletePermanently(row.Id);
					LoadData();
				}
				catch (Exception ex)
				{
					MessageBox.Show(this, ex.Message, "Ошибка удаления");
				}
			}
		}
	}
}



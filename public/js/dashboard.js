
document.addEventListener("DOMContentLoaded", function() {
  const ctx = document.getElementById('loanChart');
  if (ctx) {
    new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Paid', 'Remaining'],
        datasets: [{
          data: [42000, 28000],
          backgroundColor: ['#1abc9c', '#ecf0f1'],
          borderWidth: 1
        }]
      },
      options: {
        plugins: {
          legend: { position: 'bottom' }
        }
      }
    });
  }
});


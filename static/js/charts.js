// Chart.js configurations and utilities for Candidate Filtration System
// Analytics dashboard chart implementations

class CandidateCharts {
    constructor() {
        this.chartConfigs = {
            statusChart: {
                type: 'doughnut',
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                padding: 20,
                                usePointStyle: true
                            }
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.parsed;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = ((value / total) * 100).toFixed(1);
                                    return `${label}: ${value} (${percentage}%)`;
                                }
                            }
                        }
                    },
                    cutout: '60%'
                }
            },
            experienceChart: {
                type: 'bar',
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        },
                        tooltip: {
                            callbacks: {
                                title: function(context) {
                                    return `Experience: ${context[0].label}`;
                                },
                                label: function(context) {
                                    const value = context.parsed.y;
                                    return `${value} candidate${value !== 1 ? 's' : ''}`;
                                }
                            }
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                stepSize: 1
                            },
                            grid: {
                                color: 'rgba(0,0,0,0.1)'
                            }
                        },
                        x: {
                            grid: {
                                display: false
                            }
                        }
                    },
                    elements: {
                        bar: {
                            borderRadius: 4,
                            borderSkipped: false
                        }
                    }
                }
            },
            skillsChart: {
                type: 'horizontalBar',
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        x: {
                            beginAtZero: true,
                            grid: {
                                color: 'rgba(0,0,0,0.1)'
                            }
                        },
                        y: {
                            grid: {
                                display: false
                            }
                        }
                    }
                }
            }
        };
    }

    // Create status distribution chart
    createStatusChart(canvasId, data) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) {
            console.error(`Canvas element ${canvasId} not found`);
            return null;
        }

        const chartData = {
            labels: ['Passed', 'Failed', 'Pending'],
            datasets: [{
                data: [
                    data.candidates?.passed || 0,
                    data.candidates?.failed || 0,
                    data.candidates?.pending || 0
                ],
                backgroundColor: [
                    '#28a745',  // Green for passed
                    '#dc3545',  // Red for failed  
                    '#ffc107'   // Yellow for pending
                ],
                borderColor: '#fff',
                borderWidth: 2,
                hoverBorderWidth: 3
            }]
        };

        return new Chart(ctx, {
            ...this.chartConfigs.statusChart,
            data: chartData
        });
    }

    // Create experience distribution chart
    createExperienceChart(canvasId, data) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) {
            console.error(`Canvas element ${canvasId} not found`);
            return null;
        }

        const experienceData = data.demographics?.experience_distribution || {};
        
        const chartData = {
            labels: Object.keys(experienceData),
            datasets: [{
                label: 'Candidates',
                data: Object.values(experienceData),
                backgroundColor: [
                    '#007bff',
                    '#28a745', 
                    '#ffc107'
                ],
                borderColor: [
                    '#0056b3',
                    '#1e7e34',
                    '#d39e00'
                ],
                borderWidth: 1
            }]
        };

        return new Chart(ctx, {
            ...this.chartConfigs.experienceChart,
            data: chartData
        });
    }

    // Create skills popularity chart (if data available)
    createSkillsChart(canvasId, skillsData) {
        const ctx = document.getElementById(canvasId);
        if (!ctx || !skillsData) {
            console.warn(`Canvas ${canvasId} not found or no skills data provided`);
            return null;
        }

        const chartData = {
            labels: Object.keys(skillsData),
            datasets: [{
                label: 'Skill Frequency',
                data: Object.values(skillsData),
                backgroundColor: '#17a2b8',
                borderColor: '#138496',
                borderWidth: 1
            }]
        };

        return new Chart(ctx, {
            ...this.chartConfigs.skillsChart,
            data: chartData
        });
    }

    // Utility method to update chart data
    updateChart(chart, newData) {
        if (!chart) return;
        
        chart.data.datasets[0].data = newData;
        chart.update();
    }

    // Utility method to destroy chart
    destroyChart(chart) {
        if (chart && typeof chart.destroy === 'function') {
            chart.destroy();
        }
    }

    // Load and initialize all charts
    async initializeCharts() {
        try {
            // Fetch statistics data
            const response = await fetch('/api/stats');
            const statsData = await response.json();
            
            if (!statsData.success) {
                throw new Error('Failed to load statistics data');
            }

            // Initialize status chart
            this.statusChart = this.createStatusChart('statusChart', statsData.statistics);
            
            // Initialize experience chart  
            this.experienceChart = this.createExperienceChart('experienceChart', statsData.statistics);

            // Log success
            console.log('Charts initialized successfully');
            
            return {
                statusChart: this.statusChart,
                experienceChart: this.experienceChart
            };

        } catch (error) {
            console.error('Error initializing charts:', error);
            this.showChartError();
        }
    }

    // Show error message when charts fail to load
    showChartError() {
        const chartContainers = document.querySelectorAll('.chart-container');
        chartContainers.forEach(container => {
            container.innerHTML = `
                <div class="text-center p-4 text-muted">
                    <i class="fas fa-exclamation-triangle fa-2x mb-2"></i>
                    <p>Unable to load chart data</p>
                    <small>Please refresh the page to try again</small>
                </div>
            `;
        });
    }

    // Refresh charts with new data
    async refreshCharts() {
        try {
            const response = await fetch('/api/stats');
            const statsData = await response.json();
            
            if (statsData.success && this.statusChart && this.experienceChart) {
                const stats = statsData.statistics;
                
                // Update status chart
                this.updateChart(this.statusChart, [
                    stats.candidates.passed,
                    stats.candidates.failed, 
                    stats.candidates.pending
                ]);

                // Update experience chart
                this.updateChart(this.experienceChart, 
                    Object.values(stats.demographics.experience_distribution)
                );
                
                console.log('Charts refreshed successfully');
            }
        } catch (error) {
            console.error('Error refreshing charts:', error);
        }
    }
}

// Initialize charts when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Only initialize on stats/analytics pages
    if (document.getElementById('statusChart') || document.getElementById('experienceChart')) {
        window.candidateCharts = new CandidateCharts();
        window.candidateCharts.initializeCharts();
    }
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CandidateCharts;
}

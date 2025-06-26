package search

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/storage"
)

func BenchmarkFuzzySearchEngine_IndexCommands(b *testing.B) {
	sizes := []int{100, 1000, 10000}
	
	for _, size := range sizes {
		b.Run(fmt.Sprintf("IndexCommands_%d", size), func(b *testing.B) {
			records := generateBenchmarkRecords(size)
			
			b.ResetTimer()
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				tmpDir := b.TempDir()
				engine := NewFuzzySearchEngine(tmpDir + "/bench_index")
				engine.Initialize()
				
				start := time.Now()
				err := engine.IndexCommands(records)
				if err != nil {
					b.Fatalf("Failed to index commands: %v", err)
				}
				
				duration := time.Since(start)
				b.ReportMetric(float64(duration.Nanoseconds())/float64(size), "ns/record")
				
				engine.Close()
			}
		})
	}
}

func BenchmarkFuzzySearchEngine_Search(b *testing.B) {
	// Setup test data once
	records := generateBenchmarkRecords(10000)
	tmpDir := b.TempDir()
	engine := NewFuzzySearchEngine(tmpDir + "/bench_search")
	engine.Initialize()
	engine.IndexCommands(records)
	defer engine.Close()
	
	queries := []string{
		"git",
		"git status",
		"ls",
		"find",
		"grep pattern",
		"docker run",
		"kubectl get",
		"npm install",
	}
	
	fuzziness := []int{0, 1, 2}
	
	for _, fuzz := range fuzziness {
		for _, query := range queries {
			b.Run(fmt.Sprintf("Search_fuzziness_%d_%s", fuzz, query), func(b *testing.B) {
				opts := &FuzzySearchOptions{
					Fuzziness:     fuzz,
					MaxCandidates: 100,
					MinScore:      0.1,
				}
				
				b.ResetTimer()
				b.ReportAllocs()
				
				for i := 0; i < b.N; i++ {
					start := time.Now()
					results, err := engine.Search(query, opts)
					duration := time.Since(start)
					
					if err != nil {
						b.Fatalf("Search failed: %v", err)
					}
					
					// Validate performance requirement: sub-200ms
					if duration > 200*time.Millisecond {
						b.Errorf("Search took %v, exceeds 200ms requirement", duration)
					}
					
					b.ReportMetric(float64(duration.Nanoseconds()), "ns/search")
					b.ReportMetric(float64(len(results)), "results")
				}
			})
		}
	}
}

func BenchmarkFuzzySearchEngine_SearchByDatasetSize(b *testing.B) {
	sizes := []int{1000, 10000, 50000, 100000}
	query := "git status"
	
	for _, size := range sizes {
		b.Run(fmt.Sprintf("Search_%d_records", size), func(b *testing.B) {
			records := generateBenchmarkRecords(size)
			tmpDir := b.TempDir()
			engine := NewFuzzySearchEngine(tmpDir + "/bench_size")
			engine.Initialize()
			engine.IndexCommands(records)
			defer engine.Close()
			
			opts := &FuzzySearchOptions{
				Fuzziness:     1,
				MaxCandidates: 100,
				MinScore:      0.1,
			}
			
			b.ResetTimer()
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				start := time.Now()
				results, err := engine.Search(query, opts)
				duration := time.Since(start)
				
				if err != nil {
					b.Fatalf("Search failed: %v", err)
				}
				
				// Critical requirement: sub-200ms for 100k+ records
				if size >= 100000 && duration > 200*time.Millisecond {
					b.Errorf("Search on %d records took %v, exceeds 200ms requirement", size, duration)
				}
				
				b.ReportMetric(float64(duration.Nanoseconds()), "ns/search")
				b.ReportMetric(float64(len(results)), "results")
				b.ReportMetric(float64(size), "dataset_size")
			}
		})
	}
}

func BenchmarkSearchService_SearchComparison(b *testing.B) {
	// Compare fuzzy search vs regular search performance
	tmpDir := b.TempDir()
	service := setupBenchmarkSearchService(b, tmpDir)
	defer service.Close()
	
	query := "git status"
	
	b.Run("FuzzySearch", func(b *testing.B) {
		req := &SearchRequest{
			Query:          query,
			Limit:          50,
			UseFuzzySearch: true,
			FuzzyOptions: &FuzzySearchOptions{
				Fuzziness:     1,
				MaxCandidates: 100,
				MinScore:      0.1,
			},
		}
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			start := time.Now()
			response, err := service.Search(req)
			duration := time.Since(start)
			
			if err == nil {
				b.ReportMetric(float64(duration.Nanoseconds()), "ns/search")
				b.ReportMetric(float64(response.TotalMatches), "results")
				if response.UsedFuzzySearch {
					b.ReportMetric(1, "used_fuzzy")
				}
			}
		}
	})
	
	b.Run("RegularSearch", func(b *testing.B) {
		req := &SearchRequest{
			Query:          query,
			Limit:          50,
			UseFuzzySearch: false,
			UseCache:       false,
		}
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			start := time.Now()
			response, err := service.Search(req)
			duration := time.Since(start)
			
			if err == nil {
				b.ReportMetric(float64(duration.Nanoseconds()), "ns/search")
				b.ReportMetric(float64(response.TotalMatches), "results")
			}
		}
	})
}

func BenchmarkFuzzySearchEngine_RebuildIndex(b *testing.B) {
	sizes := []int{1000, 5000, 10000}
	
	for _, size := range sizes {
		b.Run(fmt.Sprintf("RebuildIndex_%d", size), func(b *testing.B) {
			records := generateBenchmarkRecords(size)
			
			b.ResetTimer()
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				tmpDir := b.TempDir()
				engine := NewFuzzySearchEngine(tmpDir + "/bench_rebuild")
				engine.Initialize()
				
				start := time.Now()
				err := engine.RebuildIndex(records)
				duration := time.Since(start)
				
				if err != nil {
					b.Fatalf("Failed to rebuild index: %v", err)
				}
				
				b.ReportMetric(float64(duration.Nanoseconds())/float64(size), "ns/record")
				
				engine.Close()
			}
		})
	}
}

func BenchmarkFuzzySearchEngine_ConcurrentSearch(b *testing.B) {
	records := generateBenchmarkRecords(10000)
	tmpDir := b.TempDir()
	engine := NewFuzzySearchEngine(tmpDir + "/bench_concurrent")
	engine.Initialize()
	engine.IndexCommands(records)
	defer engine.Close()
	
	queries := []string{"git", "ls", "find", "grep", "docker"}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	b.RunParallel(func(pb *testing.PB) {
		opts := &FuzzySearchOptions{
			Fuzziness:     1,
			MaxCandidates: 50,
			MinScore:      0.1,
		}
		
		queryIndex := 0
		for pb.Next() {
			query := queries[queryIndex%len(queries)]
			queryIndex++
			
			start := time.Now()
			results, err := engine.Search(query, opts)
			duration := time.Since(start)
			
			if err != nil {
				b.Fatalf("Concurrent search failed: %v", err)
			}
			
			// Ensure concurrent searches still meet performance requirements
			if duration > 300*time.Millisecond {
				b.Errorf("Concurrent search took %v, too slow", duration)
			}
			
			_ = results // Use results to prevent optimization
		}
	})
}

func BenchmarkFuzzySearchEngine_MemoryUsage(b *testing.B) {
	sizes := []int{1000, 10000, 50000}
	
	for _, size := range sizes {
		b.Run(fmt.Sprintf("MemoryUsage_%d", size), func(b *testing.B) {
			records := generateBenchmarkRecords(size)
			
			b.ResetTimer()
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				tmpDir := b.TempDir()
				engine := NewFuzzySearchEngine(tmpDir + "/bench_memory")
				engine.Initialize()
				
				// Measure memory during indexing
				engine.IndexCommands(records)
				
				// Measure memory during search
				opts := &FuzzySearchOptions{
					Fuzziness:     1,
					MaxCandidates: 100,
					MinScore:      0.1,
				}
				
				_, err := engine.Search("git status", opts)
				if err != nil {
					b.Fatalf("Search failed: %v", err)
				}
				
				engine.Close()
			}
		})
	}
}

func BenchmarkFuzzySearchOptions_Impact(b *testing.B) {
	records := generateBenchmarkRecords(5000)
	tmpDir := b.TempDir()
	engine := NewFuzzySearchEngine(tmpDir + "/bench_options")
	engine.Initialize()
	engine.IndexCommands(records)
	defer engine.Close()
	
	query := "git status"
	
	// Test impact of different option values
	fuzzinessValues := []int{0, 1, 2}
	candidateValues := []int{50, 100, 500, 1000}
	scoreValues := []float64{0.01, 0.1, 0.5}
	
	for _, fuzz := range fuzzinessValues {
		for _, candidates := range candidateValues {
			for _, minScore := range scoreValues {
				testName := fmt.Sprintf("fuzz_%d_candidates_%d_score_%.2f", fuzz, candidates, minScore)
				b.Run(testName, func(b *testing.B) {
					opts := &FuzzySearchOptions{
						Fuzziness:     fuzz,
						MaxCandidates: candidates,
						MinScore:      minScore,
					}
					
					b.ResetTimer()
					b.ReportAllocs()
					
					for i := 0; i < b.N; i++ {
						start := time.Now()
						results, err := engine.Search(query, opts)
						duration := time.Since(start)
						
						if err != nil {
							b.Fatalf("Search failed: %v", err)
						}
						
						b.ReportMetric(float64(duration.Nanoseconds()), "ns/search")
						b.ReportMetric(float64(len(results)), "results")
					}
				})
			}
		}
	}
}

// Helper functions for benchmarks

func generateBenchmarkRecords(count int) []*storage.CommandRecord {
	records := make([]*storage.CommandRecord, count)
	baseTime := time.Now()
	
	commands := []string{
		"git status", "git commit -m 'update'", "git push origin main", "git pull",
		"ls -la", "ls -l", "ls", "ls -la | grep txt",
		"find . -name '*.go'", "find . -type f", "find /var/log -name '*.log'",
		"grep -r 'pattern' .", "grep -n 'func' *.go", "grep -i 'error' logs/",
		"docker ps", "docker run ubuntu", "docker build -t app .", "docker logs container",
		"kubectl get pods", "kubectl describe pod", "kubectl apply -f config.yaml",
		"npm install", "npm start", "npm run build", "npm test",
		"go build", "go test", "go mod tidy", "go run main.go",
		"python script.py", "python -m venv env", "pip install requests",
		"make build", "make test", "make clean", "make install",
		"ssh user@server", "scp file.txt user@server:/path/", "rsync -av src/ dest/",
		"curl -X GET https://api.example.com", "wget https://example.com/file.zip",
		"cat file.txt", "head -10 file.txt", "tail -f /var/log/app.log",
		"echo 'hello world'", "echo $PATH", "export VAR=value",
		"cd /home/user", "cd ..", "cd ~/projects", "pwd",
		"mkdir new_dir", "rmdir old_dir", "rm -rf temp/", "cp src dest",
		"mv old_name new_name", "chmod 755 script.sh", "chown user:group file",
		"ps aux", "top", "htop", "kill -9 1234", "killall process_name",
		"df -h", "du -sh *", "free -m", "uptime", "who", "w",
	}
	
	workDirs := []string{
		"/home/user", "/home/user/projects", "/home/user/documents",
		"/var/www/html", "/opt/app", "/tmp", "/var/log",
		"/home/user/go/src/project", "/home/user/.config",
	}
	
	hostnames := []string{"laptop", "server1", "workstation", "dev-box", "prod-server"}
	users := []string{"user", "admin", "developer", "ops"}
	shells := []string{"bash", "zsh", "fish"}
	
	for i := 0; i < count; i++ {
		records[i] = &storage.CommandRecord{
			Command:    commands[rand.Intn(len(commands))],
			ExitCode:   rand.Intn(3), // 0, 1, or 2
			Duration:   int64(rand.Intn(5000) + 10), // 10-5010ms
			WorkingDir: workDirs[rand.Intn(len(workDirs))],
			Timestamp:  baseTime.Add(time.Duration(i) * time.Second).UnixMilli(),
			SessionID:  fmt.Sprintf("session-%d", rand.Intn(10)),
			Hostname:   hostnames[rand.Intn(len(hostnames))],
			GitBranch:  []string{"main", "develop", "feature/new", ""}[rand.Intn(4)],
			GitRoot:    "/home/user/projects/repo",
			User:       users[rand.Intn(len(users))],
			Shell:      shells[rand.Intn(len(shells))],
			Version:    1,
			CreatedAt:  baseTime.UnixMilli(),
		}
	}
	
	return records
}

func setupBenchmarkSearchService(b *testing.B, tmpDir string) *SearchService {
	cfg := &config.Config{
		DataDir: tmpDir,
		Cache: config.CacheConfig{
			HotCacheSize:    1000,
			SearchBatchSize: 5000,
			MaxMemoryMB:     100,
		},
	}
	
	service := NewSearchService(nil, nil, cfg)
	
	opts := &SearchOptions{
		EnableFuzzySearch: true,
		FuzzyIndexPath:    tmpDir + "/bench_service_index",
		WarmupCache:       false,
	}
	
	service.Initialize(opts)
	return service
}
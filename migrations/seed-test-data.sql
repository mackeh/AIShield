-- Seed data for testing analytics dashboard
-- Run after migrations are applied

-- Clean existing test data (optional)
-- DELETE FROM findings;
-- DELETE FROM scans;

-- Seed organizations and teams
DO $$
DECLARE
  scan_uuid UUID;
  org_ids TEXT[] := ARRAY['github/acme-corp', 'github/test-startup', 'gitlab/enterprise'];
  team_ids TEXT[] := ARRAY['backend', 'frontend', 'mobile', 'devops'];
  repos TEXT[] := ARRAY[
    'github.com/acme/api-server',
    'github.com/acme/web-app',
    'github.com/acme/mobile-ios',
    'github.com/test/product-api',
    'github.com/test/admin-panel'
  ];
  i INTEGER;
  j INTEGER;
  random_date TIMESTAMPTZ;
BEGIN
  -- Generate 100 historical scans over last 30 days
  FOR i IN 1..100 LOOP
    -- Random timestamp in last 30 days
    random_date := NOW() - (random() * INTERVAL '30 days');
    
    -- Insert scan
    INSERT INTO scans (
      org_id,
      team_id,
      repo_id,
      repo_name,
      target_path,
      branch,
      commit_sha,
      cli_version,
      total_findings,
      critical_count,
      high_count,
      medium_count,
      low_count,
      info_count,
      ai_estimated_count,
      scan_duration_ms,
      files_scanned,
      rules_loaded,
      timestamp
    ) VALUES (
      org_ids[1 + floor(random() * array_length(org_ids, 1))::int],
      team_ids[1 + floor(random() * array_length(team_ids, 1))::int],
      repos[1 + floor(random() * array_length(repos, 1))::int],
      'repo-' || i,
      CASE WHEN random() > 0.5 THEN 'src/' ELSE '.' END,
      CASE WHEN random() > 0.3 THEN 'main' ELSE 'develop' END,
      md5(random()::text),
      '0.3.0',
      20 + floor(random() * 30)::int,               -- total_findings (20-49)
      floor(random() * 5)::int,                     -- critical
      floor(random() * 15)::int,                    -- high
      floor(random() * 20)::int,                    -- medium
      floor(random() * 10)::int,                    -- low
      0,                                             -- info
      floor(random() * 20)::int,                    -- AI estimated (always <= total_findings)
      500 + floor(random() * 3000)::int,            -- scan duration
      50 + floor(random() * 500)::int,              -- files
      169,                                           -- rules
      random_date
    ) RETURNING scan_id INTO scan_uuid;
    
    -- Insert 3-10 findings per scan
    FOR j IN 1..(3 + floor(random() * 8)::int) LOOP
      INSERT INTO findings (
        scan_id,
        finding_hash,
        rule_id,
        rule_title,
        severity,
        file_path,
        line_number,
        ai_confidence,
        snippet,
        ai_tendency,
        fix_suggestion,
        cwe_id,
        owasp_category
      ) VALUES (
        scan_uuid,
        md5(random()::text || i::text || j::text),
        CASE floor(random() * 5)::int
          WHEN 0 THEN 'AISHIELD-PY-CRYPTO-001'
          WHEN 1 THEN 'AISHIELD-JS-INJECT-001'
          WHEN 2 THEN 'AISHIELD-PY-AUTH-002'
          WHEN 3 THEN 'AISHIELD-GO-MISCONFIG-003'
          ELSE 'AISHIELD-JS-CRYPTO-004'
        END,
        CASE floor(random() * 5)::int
          WHEN 0 THEN 'Weak hash algorithm (MD5/SHA1)'
          WHEN 1 THEN 'SQL injection via string concatenation'
          WHEN 2 THEN 'Timing-unsafe password comparison'
          WHEN 3 THEN 'Hardcoded secret in source'
          ELSE 'Weak random number generation'
        END,
        CASE floor(random() * 5)::int
          WHEN 0 THEN 'critical'
          WHEN 1 THEN 'high'
          WHEN 2 THEN 'high'
          WHEN 3 THEN 'medium'
          ELSE 'low'
        END,
        'src/' || CASE floor(random() * 4)::int
          WHEN 0 THEN 'auth.py'
          WHEN 1 THEN 'database.js'
          WHEN 2 THEN 'config.go'
          ELSE 'utils.ts'
        END,
        floor(random() * 500)::int + 1,
        0.5 + (random() * 0.5),                     -- AI confidence 0.5-1.0
        'hashlib.md5(password.encode())',
        'LLMs frequently suggest MD5 from outdated tutorials',
        'Use bcrypt or argon2 for password hashing',
        'CWE-327',
        'A02:2021'
      );
    END LOOP;
  END LOOP;
  
  RAISE NOTICE 'Inserted % scans with findings', i;
END $$;

-- Refresh materialized views with new data
SELECT refresh_analytics_views();

-- Verify seed data
SELECT 
  'Scans' as table_name, 
  count(*) as row_count,
  min(timestamp) as earliest,
  max(timestamp) as latest
FROM scans
UNION ALL
SELECT 
  'Findings', 
  count(*),
  min(first_seen),
  max(last_seen)
FROM findings;

-- Show sample org summary
SELECT 
  org_id,
  count(*) as scans,
  sum(total_findings) as total_findings,
  avg(ai_ratio)::numeric(4,2) as avg_ai_ratio
FROM scans
GROUP BY org_id
ORDER BY scans DESC;

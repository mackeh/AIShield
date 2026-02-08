-- Add AI metrics tracking to findings table
-- Migration: 20260208_add_ai_metrics

ALTER TABLE findings 
ADD COLUMN IF NOT EXISTS ai_tool VARCHAR(50),
ADD COLUMN IF NOT EXISTS confidence_score DECIMAL(5,2),
ADD COLUMN IF NOT EXISTS is_ai_generated BOOLEAN DEFAULT false;

-- Create indexes for AI metrics queries
CREATE INDEX IF NOT EXISTS idx_findings_ai_tool ON findings(ai_tool);
CREATE INDEX IF NOT EXISTS idx_findings_confidence ON findings(confidence_score);
CREATE INDEX IF NOT EXISTS idx_findings_ai_generated ON findings(is_ai_generated);

-- Update existing data to mark AI-generated findings
-- Pattern: If ai_metadata is present, it's AI-generated
UPDATE findings 
SET is_ai_generated = true 
WHERE ai_metadata IS NOT NULL AND ai_metadata != '';

-- Comment on columns
COMMENT ON COLUMN findings.ai_tool IS 'AI tool that detected this finding (e.g., CodeQL, Semgrep, GPT-4)';
COMMENT ON COLUMN findings.confidence_score IS 'AI confidence score (0-100)';
COMMENT ON COLUMN findings.is_ai_generated IS 'Whether this finding was detected by AI';

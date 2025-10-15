-- Upgrade: Change score columns from INT to DECIMAL(15, 10)

-- 1. Modify the 'submissions' table
-- This table stores every single submission made.
ALTER TABLE `submissions`
MODIFY COLUMN `score` DECIMAL(15, 10) DEFAULT NULL;

-- 2. Modify the 'contests_submissions' table
-- This table stores the final accepted submission for each problem in a contest.
ALTER TABLE `contests_submissions`
MODIFY COLUMN `score` DECIMAL(15, 10) NOT NULL;
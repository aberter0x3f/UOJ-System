-- Downgrade: Change score columns back from DECIMAL to INT

-- 1. Revert the 'submissions' table
ALTER TABLE `submissions`
MODIFY COLUMN `score` INT(11) DEFAULT NULL;

-- 2. Revert the 'contests_submissions' table
ALTER TABLE `contests_submissions`
MODIFY COLUMN `score` INT(11) NOT NULL;
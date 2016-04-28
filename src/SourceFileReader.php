<?php
namespace Rollbar;

class SourceFileReader {
    public function readAsArray($file_path) {
        return file($file_path);
    }
}
